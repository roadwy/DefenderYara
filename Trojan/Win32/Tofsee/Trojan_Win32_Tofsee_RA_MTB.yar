
rule Trojan_Win32_Tofsee_RA_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b f7 c1 ee 05 33 c8 03 b5 90 01 04 0f 57 c0 81 3d 90 01 04 72 07 00 00 90 00 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}