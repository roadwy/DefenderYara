
rule Trojan_Win32_Redline_GMW_MTB{
	meta:
		description = "Trojan:Win32/Redline.GMW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 c4 40 50 e8 ?? ?? ?? ?? fe 0c 3e c7 04 24 } //10
		$a_03_1 = {33 d2 8b c6 f7 74 24 24 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8a ba ?? ?? ?? ?? 32 fb } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}