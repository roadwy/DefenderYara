
rule TrojanSpy_Win32_BrobanMos_A{
	meta:
		description = "TrojanSpy:Win32/BrobanMos.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6e 74 61 64 6f 72 32 61 } //1 contador2a
		$a_01_1 = {5c 00 6c 00 6f 00 61 00 64 00 65 00 72 00 46 00 69 00 72 00 65 00 66 00 6f 00 78 00 2e 00 76 00 62 00 70 00 } //1 \loaderFirefox.vbp
		$a_01_2 = {49 73 58 50 49 4c 6f 61 64 65 64 } //1 IsXPILoaded
		$a_01_3 = {72 65 73 6f 75 72 63 65 73 2f 66 69 72 65 66 6f 78 65 78 74 2f 64 61 74 61 2f 62 61 63 6b 67 72 6f 75 6e 64 2e 6a 73 50 4b } //1 resources/firefoxext/data/background.jsPK
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}