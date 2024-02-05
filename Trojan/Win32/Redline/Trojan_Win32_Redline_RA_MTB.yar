
rule Trojan_Win32_Redline_RA_MTB{
	meta:
		description = "Trojan:Win32/Redline.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 c9 8b d1 83 c0 21 b9 60 01 00 00 42 e2 fd 03 c2 6a 00 50 c3 33 c0 5f 5e 8b 4d fc 33 cd e8 } //00 00 
	condition:
		any of ($a_*)
 
}