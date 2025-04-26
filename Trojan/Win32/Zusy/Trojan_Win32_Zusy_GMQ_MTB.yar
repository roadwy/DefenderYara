
rule Trojan_Win32_Zusy_GMQ_MTB{
	meta:
		description = "Trojan:Win32/Zusy.GMQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 04 01 00 00 56 53 ff 15 ?? ?? ?? ?? a1 ?? ?? a5 00 89 35 ?? 89 a5 00 8b fe 38 18 ?? ?? 8b f8 8d 45 f8 50 8d 45 fc 50 } //10
		$a_03_1 = {8b 45 fc 83 c4 14 48 89 35 ?? 89 a5 00 5f 5e } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}