
rule Backdoor_Win32_MQTTClient_A{
	meta:
		description = "Backdoor:Win32/MQTTClient.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 08 00 00 "
		
	strings :
		$a_01_0 = {4d 51 54 54 43 6c 69 65 6e 74 } //1 MQTTClient
		$a_01_1 = {76 20 2b 3d 20 28 62 79 74 65 20 26 20 30 78 37 46 29 20 2a 20 6d } //1 v += (byte & 0x7F) * m
		$a_01_2 = {6d 61 6b 65 5f 63 6f 6e 6e 65 63 74 28 63 6c 69 65 6e 74 5f 69 64 3a } //1 make_connect(client_id:
		$a_01_3 = {6d 61 6b 65 5f 70 6c 75 67 69 6e 5f 64 61 74 61 28 70 6c 75 67 69 6e 5f 69 64 3a } //1 make_plugin_data(plugin_id:
		$a_01_4 = {70 6c 75 67 69 6e 73 20 3d 20 6a 73 6f 6e 2e 6c 6f 61 64 73 28 70 61 79 6c 6f 61 64 2e 64 65 63 6f 64 65 28 29 29 } //1 plugins = json.loads(payload.decode())
		$a_01_5 = {5c 27 53 65 6e 64 44 61 74 61 54 6f 53 65 72 76 65 72 5c 27 3a 20 6c 61 6d 62 64 61 20 64 61 74 61 2c 20 70 69 64 3d 70 6c 75 67 69 6e 5f 69 64 3a 20 73 65 6c 66 2e 5f 73 65 6e 64 5f 72 65 73 70 6f 6e 73 65 28 70 69 64 2c 20 64 61 74 61 29 } //1 \'SendDataToServer\': lambda data, pid=plugin_id: self._send_response(pid, data)
		$a_01_6 = {70 61 79 6c 6f 61 64 20 3d 20 6a 73 6f 6e 2e 64 75 6d 70 73 28 7b 5c 27 70 6c 75 67 69 6e 5c 27 3a 20 70 6c 75 67 69 6e 5f 69 64 2c 20 5c 27 61 63 74 69 6f 6e 5c 27 3a 20 61 63 74 69 6f 6e 2c 20 5c 27 64 61 74 61 5c 27 3a 20 64 61 74 61 7d 29 2e 65 6e 63 6f 64 65 28 29 } //1 payload = json.dumps({\'plugin\': plugin_id, \'action\': action, \'data\': data}).encode()
		$a_01_7 = {43 4f 4e 4e 45 43 54 2c 20 43 4f 4e 4e 41 43 4b 2c 20 50 49 4e 47 52 45 51 2c 20 50 49 4e 47 52 45 53 50 2c 20 44 49 53 43 4f 4e 4e 45 43 54 2c 20 50 4c 55 47 49 4e 5f 44 41 54 41 2c 20 50 4c 55 47 49 4e 5f 43 4f 44 45 } //1 CONNECT, CONNACK, PINGREQ, PINGRESP, DISCONNECT, PLUGIN_DATA, PLUGIN_CODE
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=4
 
}