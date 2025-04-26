
rule Trojan_Win32_Glupteba_MT_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.MT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {56 33 f6 85 ff 7e ?? 55 8b 2d ?? ?? ?? ?? 8b ff 83 ff 2d 75 14 } //10
		$a_00_1 = {30 04 1e 81 ff 91 05 00 00 75 0e } //10
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10) >=20
 
}