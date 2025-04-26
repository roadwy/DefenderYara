
rule Trojan_Win32_Redline_GBM_MTB{
	meta:
		description = "Trojan:Win32/Redline.GBM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f af c1 a3 ?? ?? ?? ?? 0f b7 05 ?? ?? ?? ?? 99 01 45 a8 11 55 ac 0f b6 4d f2 81 f1 fe 00 00 00 88 4d f8 8d 95 } //10
		$a_03_1 = {66 89 45 d4 8a 8c 35 ?? ?? ?? ?? 80 f1 1b 66 0f b6 d1 66 89 94 75 ?? ?? ?? ?? 46 83 fe 0c 0f 8c } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}