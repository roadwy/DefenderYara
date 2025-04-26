
rule Trojan_Win32_Tofsee_EAPW_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.EAPW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 f7 8b 7d f8 33 f3 2b fe 89 7d f8 3d b6 05 00 00 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}