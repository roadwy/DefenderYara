
rule Trojan_Win32_Glupteba_KT_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.KT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {56 33 f6 85 ff 7e ?? 55 8b 2d ?? ?? ?? ?? 83 ff 2d 75 1e } //10
		$a_00_1 = {30 04 33 81 ff 91 05 00 00 75 31 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10) >=20
 
}