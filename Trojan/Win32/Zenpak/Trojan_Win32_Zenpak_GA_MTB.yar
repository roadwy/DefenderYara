
rule Trojan_Win32_Zenpak_GA_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 c0 8a 44 34 90 01 01 81 e1 90 01 04 03 c1 83 c4 90 01 01 25 90 02 30 48 0d 90 01 04 40 8a 54 04 90 01 01 8a 03 32 c2 88 03 43 4d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}