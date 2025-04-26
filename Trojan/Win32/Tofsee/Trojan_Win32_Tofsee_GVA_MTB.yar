
rule Trojan_Win32_Tofsee_GVA_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 f7 8b 7d f8 33 f3 2b fe 89 7d f8 3d b6 05 00 00 } //3
		$a_01_1 = {33 c1 8b 4d ec 03 cf 33 c1 29 45 f0 a1 5c 8a e5 04 3d d5 01 00 00 75 33 } //3
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3) >=3
 
}