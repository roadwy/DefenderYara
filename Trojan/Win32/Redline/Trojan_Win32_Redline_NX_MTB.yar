
rule Trojan_Win32_Redline_NX_MTB{
	meta:
		description = "Trojan:Win32/Redline.NX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {88 d9 8a 68 01 31 f1 66 89 08 0f b6 4d 02 30 48 02 eb 99 } //10
		$a_03_1 = {8b 45 e4 8b 0c b8 31 c0 8d b4 26 ?? ?? ?? ?? ?? 0f b6 14 86 30 14 01 83 c0 ?? 8b 13 39 d0 7c } //10
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}