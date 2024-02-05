
rule Trojan_Win32_Gozi_MX_MTB{
	meta:
		description = "Trojan:Win32/Gozi.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {c1 e9 05 03 4d 90 01 01 03 45 90 01 01 33 c1 8b 4d 90 01 01 03 cf 33 c1 29 45 90 01 01 81 3d 90 01 04 d5 01 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}