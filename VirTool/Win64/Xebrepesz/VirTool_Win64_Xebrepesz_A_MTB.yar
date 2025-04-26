
rule VirTool_Win64_Xebrepesz_A_MTB{
	meta:
		description = "VirTool:Win64/Xebrepesz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 09 00 00 "
		
	strings :
		$a_01_0 = {2e 65 78 65 63 75 74 65 43 6f 6d 6d 61 6e 64 41 6e 64 48 61 6e 64 6c 65 43 44 } //1 .executeCommandAndHandleCD
		$a_01_1 = {2e 61 65 73 45 43 42 44 6e 63 72 79 70 74 } //1 .aesECBDncrypt
		$a_01_2 = {29 2e 48 6f 73 74 6e 61 6d 65 } //1 ).Hostname
		$a_01_3 = {2e 69 6e 6a 65 63 74 54 61 73 6b } //1 .injectTask
		$a_03_4 = {73 6f 63 6b 73 ?? 2e 48 61 6e 64 6c 65 43 6f 6e 6e 65 63 74 69 6f 6e } //1
		$a_01_5 = {2e 54 43 50 43 6c 69 65 6e 74 } //1 .TCPClient
		$a_01_6 = {52 65 6d 6f 74 65 41 64 64 72 } //1 RemoteAddr
		$a_01_7 = {6d 61 78 50 61 79 6c 6f 61 64 53 69 7a 65 46 6f 72 57 72 69 74 65 } //1 maxPayloadSizeForWrite
		$a_01_8 = {53 65 74 53 65 73 73 69 6f 6e 54 69 63 6b 65 74 } //1 SetSessionTicket
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=7
 
}