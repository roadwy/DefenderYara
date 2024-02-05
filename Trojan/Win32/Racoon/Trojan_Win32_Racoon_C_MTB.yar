
rule Trojan_Win32_Racoon_C_MTB{
	meta:
		description = "Trojan:Win32/Racoon.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b c8 8a 14 01 88 10 40 4f 75 f7 81 3d 90 01 04 9c 2b 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}