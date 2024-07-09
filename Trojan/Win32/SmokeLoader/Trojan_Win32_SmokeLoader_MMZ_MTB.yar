
rule Trojan_Win32_SmokeLoader_MMZ_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.MMZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 18 0b 53 ?? ec 04 ?? 04 ?? 30 00 00 00 75 90 0a 20 00 00 eb 05 ?? ?? ?? ?? 08 74 05 } //10
		$a_03_1 = {43 16 2a c1 1c ?? 1d ?? ?? ?? ?? 55 68 ?? ?? ?? ?? 0e 3c ?? 2b 6c 9c ?? 30 3a e1 90 0a 1f 00 30 17 2c } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}