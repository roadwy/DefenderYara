
rule Trojan_Win32_Tofsee_PVC_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.PVC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 03 45 90 01 01 03 d7 33 ca 81 3d 90 01 04 72 07 00 00 c7 05 90 01 04 b4 1a 3a df 89 35 90 01 04 89 35 90 01 04 89 4d 90 01 01 75 90 00 } //2
		$a_02_1 = {8b c3 c1 e8 05 03 85 90 01 04 8d 14 1e 33 ca 81 3d 90 01 04 72 07 00 00 c7 05 90 01 04 b4 1a 3a df 89 8d 90 01 04 75 90 00 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2) >=2
 
}