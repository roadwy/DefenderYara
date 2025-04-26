
rule Trojan_Win32_Qbot_D{
	meta:
		description = "Trojan:Win32/Qbot.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {46 3a 5c 70 75 62 6c 69 63 5c 72 65 6c 5c 67 61 76 6e 6f 73 6f 66 74 2e 50 44 42 } //1 F:\public\rel\gavnosoft.PDB
		$a_01_1 = {43 68 72 6f 6d 65 61 67 61 69 6e 73 74 62 79 71 33 6a 76 53 48 } //1 Chromeagainstbyq3jvSH
		$a_01_2 = {4c 00 31 00 7a 00 62 00 75 00 74 00 74 00 65 00 72 00 31 00 62 00 72 00 6f 00 77 00 73 00 65 00 72 00 73 00 2c 00 4f 00 6d 00 6e 00 69 00 62 00 6f 00 78 00 } //1 L1zbutter1browsers,Omnibox
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}