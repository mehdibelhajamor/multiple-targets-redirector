# Multiple Targets Redirector
from burp import IBurpExtender, IHttpRequestResponse, IHttpListener, ITab 
from javax.swing import JPanel, JButton, JTextField, BoxLayout, BorderFactory, Box, JLabel, JComboBox, JOptionPane, JScrollPane
from java.awt import BorderLayout, Color, Dimension
from java.net import URL


class BurpExtender(IBurpExtender, ITab, IHttpListener):

	def processHttpMessage(self, tool, is_request, current_request):
		if self._redirect:
			if is_request:
				analyzed_request = self._helpers.analyzeRequest(current_request)
				headers = analyzed_request.getHeaders()
				protocols = [analyzed_request.getUrl().getProtocol(), u'http', u'https']

				for sp in self.subpanels:
					pannel = sp.getComponent(0)
					src_host = pannel.getComponent(1)
					src_port = pannel.getComponent(3)
					dest_host = pannel.getComponent(5)
					dest_port = pannel.getComponent(7)
					dest_protocol = pannel.getComponent(8)

					if str(analyzed_request.getUrl().getHost()) == src_host.text and analyzed_request.getUrl().getPort() == int(src_port.text):
						host_header_index = None
						for i, header in enumerate(headers):
							if header.startswith("Host:"):
								host_header_index = i
								break
						if host_header_index is not None:
							headers[host_header_index] = "Host: {}:{}".format(dest_host.text, dest_port.text)

						final_http_service = self._helpers.buildHttpService(dest_host.text, int(dest_port.text), protocols[dest_protocol.selectedIndex])
						current_request.setHttpService(final_http_service)

						final_request = self._helpers.buildHttpMessage(headers, current_request.getRequest()[analyzed_request.getBodyOffset():])
						current_request.setRequest(final_request)

	def popup(self, text):
		JOptionPane.showMessageDialog(
			self.finalpanel,
			text,
			"Burp / Multiple Targets Redirector",
			JOptionPane.WARNING_MESSAGE
		)

	def validate_input(self):
		for sp in self.subpanels:
			pannel = sp.getComponent(0)
			src_host = pannel.getComponent(1)
			src_port = pannel.getComponent(3)
			dest_host = pannel.getComponent(5)
			dest_port = pannel.getComponent(7)
			if (src_host.text == "") or (dest_host.text == "") or (not str(src_port.text).isnumeric()) or (not str(dest_port.text).isnumeric()):
				return False
		return True

	def refresh(self):
		self.mainpanel.validate()
		self.mainpanel.repaint()
		self.innerpanel.validate()
		self.innerpanel.repaint()
		self.outerpanel.validate()
		self.outerpanel.repaint()
		self.activation_panel.validate()
		self.activation_panel.repaint()
		self.finalpanel.validate()
		self.finalpanel.repaint()

	def clear(self, event):
		if self.activation_button.text == "Activate Redirection":
			for sp in self.subpanels:
				for comp in sp.getComponents():
					for cp in comp.getComponents():
						if (type(cp) != JComboBox) and (type(cp) != JLabel):
							cp.text = ""
		self.refresh()

	def click(self, event):
		if self.validate_input():
			if self.activation_button.text == "Activate Redirection":
				print('\n\n[*] Initialising New Redirections..')
				print('[+] Redirection Activated!')
				for sp in self.subpanels:
					pannel = sp.getComponent(0)
					src_host = pannel.getComponent(1)
					src_port = pannel.getComponent(3)
					dest_host = pannel.getComponent(5)
					dest_port = pannel.getComponent(7)
					dest_protocol = pannel.getComponent(8)
					print("\n[http,https]://{}:{}  --- Redirected To -->  [http,https]://{}:{}").format(src_host.text, src_port.text, dest_host.text, dest_port.text)
				self._redirect = True
				self.toggle_active(True)
			else:
				print('\n[-] Redirection Removed!')
				self._redirect = False
				self.toggle_active(False)
		else:
			self.popup("Invalid host or/and port.")
		self.refresh()
		

	def toggle_active(self, bool):
		if bool:
			self.activation_button.text = "Remove Redirection"
		else:
			self.activation_button.text = "Activate Redirection"
		for sp in self.subpanels:
			for comp in sp.getComponents():
				for cp in comp.getComponents():
					if type(cp) == JTextField:
						cp.setEditable(not bool)
					else :
						cp.setEnabled(not bool)

	def getTabCaption(self):
		return "Multiple Targets Redirector"

	def getUiPanel(self, src_host, src_port, dest_host, dest_port):
		pannel = JPanel()
		_src_host_label = JLabel("Redirect from hostname/IP :")
		_src_host = JTextField(12)
		_src_host.text = src_host
		_src_port_label = JLabel("Port :")
		_src_port = JTextField(5)
		_src_port.text = src_port
		_dest_host_label = JLabel(" To destination hostname/IP :")
		_dest_host = JTextField(12)
		_dest_host.text = dest_host
		_dest_port_label = JLabel("Port :")
		_dest_port = JTextField(5)
		_dest_port.text = dest_port
		protocols_array = ["without changing HTTP/S", "redirect as HTTP", "redirect as HTTPS"]
		protocols = JComboBox(protocols_array)

		pannel.add(_src_host_label, BorderLayout.WEST)
		pannel.add(_src_host)
		pannel.add(_src_port_label)
		pannel.add(_src_port)
		pannel.add(_dest_host_label, BorderLayout.WEST)
		pannel.add(_dest_host)
		pannel.add(_dest_port_label)
		pannel.add(_dest_port)
		pannel.add(protocols)

		return pannel

	def addPanel(self, event):
		subpanel = JPanel()
		subpanel.border = BorderFactory.createEmptyBorder(1, 1, 1, 1)
		subpanel.add(self.getUiPanel("", "", "", ""))
		self.subpanels.append(subpanel)
		self.innerpanel.add(subpanel)
		if self.activation_button.text == "Activate Redirection":
			self.toggle_active(False)
		else:
			self.toggle_active(True)
		self.refresh()

	def removePanel(self, event):
		if len(self.innerpanel.getComponents()) > 2:
			self.subpanels = self.subpanels[:-1]
			self.innerpanel.remove(self.innerpanel.getComponents()[-1])
		self.refresh()

	def getUiComponent(self):
		self.mainpanel = JPanel()
		self.innerpanel = JPanel()
		self.outerpanel = JPanel()
		self.activation_panel = JPanel()
		self.subpanels = []

		self.clear_button = JButton("Clear")
		self.clear_button.actionPerformed = self.clear
		self.activation_button = JButton("Activate Redirection")
		self.activation_button.actionPerformed = self.click
		self.add_button = JButton("+")
		self.add_button.actionPerformed = self.addPanel
		self.remove_button = JButton("-")
		self.remove_button.actionPerformed = self.removePanel

		subpanel = JPanel()
		subpanel.border = BorderFactory.createEmptyBorder(0, 0, 0, 0)
		subpanel.add(self.getUiPanel("", "", "", ""))
		self.subpanels.append(subpanel)

		self.innerpanel.border = BorderFactory.createTitledBorder("Multiple Targets Redirector")
		self.innerpanel.layout = BoxLayout(self.innerpanel, BoxLayout.Y_AXIS)
		self.innerpanel.add(Box.createVerticalGlue())
		self.innerpanel.add(self.subpanels[0])

		self.outerpanel.layout = BoxLayout(self.outerpanel, BoxLayout.Y_AXIS)
		self.outerpanel.add(self.innerpanel)

		self.activation_panel.layout = BoxLayout(self.activation_panel, BoxLayout.X_AXIS)
		self.activation_panel.add(self.clear_button)
		self.activation_panel.add(Box.createRigidArea(Dimension(5, 0)));
		self.activation_panel.add(self.activation_button)
		self.activation_panel.add(Box.createRigidArea(Dimension(5, 0)));
		self.activation_panel.add(self.remove_button)
		self.activation_panel.add(Box.createRigidArea(Dimension(5, 0)));
		self.activation_panel.add(self.add_button)

		self.outerpanel.add(self.activation_panel)

		self.mainpanel.border = BorderFactory.createEmptyBorder(20, 20, 20, 20)
		self.mainpanel.add(self.outerpanel)

		self.finalpanel = JScrollPane(self.mainpanel)
		return self.finalpanel

	def registerExtenderCallbacks(self, callbacks):
		self._redirect = False
		self._callbacks = callbacks
		self._helpers = self._callbacks.getHelpers()
		self._callbacks.setExtensionName("Multiple Targets Redirector")
		self._callbacks.printOutput('Script loaded successfully!')
		self._callbacks.addSuiteTab(self)
		self._callbacks.registerHttpListener(self)