
rule Trojan_Win64_IcedID_HW_MTB{
	meta:
		description = "Trojan:Win64/IcedID.HW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 c2 30 da 84 c0 b8 90 01 04 41 0f 45 c6 84 db 41 0f 44 c1 84 d2 41 0f 45 c6 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}