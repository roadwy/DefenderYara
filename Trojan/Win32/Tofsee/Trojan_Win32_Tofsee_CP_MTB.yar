
rule Trojan_Win32_Tofsee_CP_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.CP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {29 c0 48 23 02 83 90 01 02 f7 d8 83 90 01 02 8d 40 fe 83 90 01 02 29 f8 90 01 02 5f 21 c7 c7 90 01 06 31 01 83 90 01 02 83 90 01 02 8d 90 01 05 2d 90 01 04 ff 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}