
rule PWS_BAT_Infostealer_PAC_MTB{
	meta:
		description = "PWS:BAT/Infostealer.PAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0d 00 00 "
		
	strings :
		$a_01_0 = {65 6e 64 70 6f 69 6e 74 43 6f 6e 66 69 67 75 72 61 74 69 6f 6e 4e 61 6d 65 } //1 endpointConfigurationName
		$a_01_1 = {47 65 74 41 6c 6c 4e 65 74 77 6f 72 6b 49 6e 74 65 72 66 61 63 65 73 } //1 GetAllNetworkInterfaces
		$a_01_2 = {6c 6f 63 61 6c 68 6f 73 74 2e 49 55 73 65 72 53 65 72 76 69 63 65 75 } //1 localhost.IUserServiceu
		$a_03_3 = {52 65 70 6c 79 41 63 74 69 6f 6e [0-02] 68 74 74 70 3a 2f 2f } //1
		$a_01_4 = {47 65 74 50 68 79 73 69 63 61 6c 41 64 64 72 65 73 73 } //1 GetPhysicalAddress
		$a_01_5 = {43 6f 6e 66 69 67 75 72 61 74 69 6f 6e 4e 61 6d 65 } //1 ConfigurationName
		$a_01_6 = {73 65 74 5f 50 72 6f 78 79 41 64 64 72 65 73 73 } //1 set_ProxyAddress
		$a_01_7 = {42 61 73 69 63 48 74 74 70 42 69 6e 64 69 6e 67 } //1 BasicHttpBinding
		$a_01_8 = {43 6c 69 65 6e 74 2e 6c 6f 63 61 6c 68 6f 73 74 } //1 Client.localhost
		$a_01_9 = {45 6e 64 70 6f 69 6e 74 41 64 64 72 65 73 73 } //1 EndpointAddress
		$a_01_10 = {41 63 74 69 6f 6e 28 68 74 74 70 3a 2f 2f } //1 Action(http://
		$a_01_11 = {72 65 6d 6f 74 65 41 64 64 72 65 73 73 } //1 remoteAddress
		$a_01_12 = {53 79 73 74 65 6d 2e 58 6d 6c } //1 System.Xml
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=10
 
}