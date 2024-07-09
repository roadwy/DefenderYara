
rule Trojan_Win32_Cutwail_AQ{
	meta:
		description = "Trojan:Win32/Cutwail.AQ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 0c 11 c1 e2 02 03 da 8b 1b 68 ?? ?? ?? ?? b8 ?? ?? ?? ?? 8d 14 52 03 c2 8f 45 f8 29 55 f8 } //1
		$a_03_1 = {31 03 83 e9 04 7e 14 03 45 f8 03 45 fc 81 c3 ?? ?? ?? 00 2b 5d 10 f7 5d fc eb e5 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}