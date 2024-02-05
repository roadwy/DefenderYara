
rule Trojan_Win32_Zenpak_AV_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.AV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8d 05 98 15 54 00 31 18 01 d0 31 c2 89 f0 50 8f 05 90 15 54 00 31 3d 94 15 54 00 eb } //01 00 
		$a_01_1 = {86 4b 14 00 70 4b 14 00 54 4b 14 00 42 4b 14 00 2e 4b 14 00 1a 4b 14 00 04 4b } //00 00 
	condition:
		any of ($a_*)
 
}