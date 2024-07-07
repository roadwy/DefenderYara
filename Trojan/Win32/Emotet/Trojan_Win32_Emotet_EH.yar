
rule Trojan_Win32_Emotet_EH{
	meta:
		description = "Trojan:Win32/Emotet.EH,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 6b 6c 65 72 2e 70 64 62 } //1 jkler.pdb
		$a_01_1 = {72 00 68 00 6b 00 6c 00 77 00 65 00 6a 00 68 00 6b 00 6c 00 23 00 4a 00 4b 00 48 00 4c 00 65 00 72 00 6b 00 6c 00 } //1 rhklwejhkl#JKHLerkl
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Emotet_EH_2{
	meta:
		description = "Trojan:Win32/Emotet.EH,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {65 77 6b 6c 68 6f 6a 77 6b 6c 5c 5c 65 68 77 5c 5c 77 65 72 65 6a 57 52 4b 40 6a 6b 65 74 6a 77 72 67 2e 70 64 62 } //1 ewklhojwkl\\ehw\\werejWRK@jketjwrg.pdb
		$a_01_1 = {57 45 48 4b 4c 4a 57 4b 4c 23 40 2e 70 64 62 } //1 WEHKLJWKL#@.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}