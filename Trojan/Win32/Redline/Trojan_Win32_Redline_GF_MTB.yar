
rule Trojan_Win32_Redline_GF_MTB{
	meta:
		description = "Trojan:Win32/Redline.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 0a 66 45 33 f7 66 41 8b 6a 08 45 22 f3 41 80 f6 b6 41 0f a3 d6 49 81 c2 0a 00 00 00 36 66 89 29 41 d2 f6 66 41 0f ba e6 f6 f9 45 8b 31 } //00 00 
	condition:
		any of ($a_*)
 
}