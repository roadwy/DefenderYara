
rule Trojan_WinNT_Bibei_B{
	meta:
		description = "Trojan:WinNT/Bibei.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 45 f8 c7 45 f4 12 02 00 00 6a 00 8b 4d f8 } //1
		$a_03_1 = {eb 02 eb ab [0-1f] 2e 00 73 00 79 00 73 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}