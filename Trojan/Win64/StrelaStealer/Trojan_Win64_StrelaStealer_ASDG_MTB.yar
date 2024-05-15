
rule Trojan_Win64_StrelaStealer_ASDG_MTB{
	meta:
		description = "Trojan:Win64/StrelaStealer.ASDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {41 57 41 56 41 55 41 54 56 57 55 53 b8 90 01 02 00 00 e8 90 01 03 00 48 29 c4 48 8d 84 24 90 01 02 00 00 48 89 c1 48 8d 15 90 01 03 00 41 b8 04 00 00 00 e8 90 01 03 00 48 8d 0d 90 01 03 00 48 89 ca 48 81 c2 90 00 } //05 00 
		$a_03_1 = {41 57 41 56 41 55 41 54 56 57 55 53 48 81 ec 90 01 02 00 00 48 8d 84 24 90 01 02 00 00 48 89 c1 48 8d 15 90 01 03 00 41 b8 04 00 00 00 e8 90 01 03 00 48 8d 0d 90 01 03 00 48 89 ca 48 81 c2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}