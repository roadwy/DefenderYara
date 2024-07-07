
rule Trojan_BAT_Vhorst_A{
	meta:
		description = "Trojan:BAT/Vhorst.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 00 54 00 72 00 6f 00 6a 00 5c 00 47 00 65 00 6e 00 65 00 72 00 61 00 74 00 6f 00 72 00 54 00 72 00 6f 00 6a 00 5c 00 73 00 76 00 68 00 6f 00 72 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //1 \Troj\GeneratorTroj\svhorst.exe
		$a_01_1 = {66 00 74 00 70 00 2e 00 70 00 68 00 70 00 6e 00 65 00 74 00 2e 00 75 00 73 00 } //1 ftp.phpnet.us
		$a_01_2 = {5c 00 44 00 6c 00 6c 00 63 00 61 00 63 00 68 00 65 00 5c 00 77 00 69 00 6e 00 6c 00 6f 00 67 00 6f 00 6e 00 2e 00 64 00 65 00 6c 00 } //1 \Dllcache\winlogon.del
		$a_01_3 = {4d 61 69 6c 41 64 64 72 65 73 73 43 6f 6c 6c 65 63 74 69 6f 6e } //1 MailAddressCollection
		$a_01_4 = {48 6f 6f 6b 43 61 6c 6c 62 61 63 6b } //1 HookCallback
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}