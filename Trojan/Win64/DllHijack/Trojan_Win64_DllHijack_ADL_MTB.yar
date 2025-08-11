
rule Trojan_Win64_DllHijack_ADL_MTB{
	meta:
		description = "Trojan:Win64/DllHijack.ADL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 89 44 24 48 48 8d 84 24 80 00 00 00 48 89 44 24 40 48 89 74 24 38 48 89 74 24 30 c7 44 24 28 04 00 00 00 89 74 24 20 45 33 c9 45 33 c0 49 8b d6 33 c9 } //2
		$a_03_1 = {8d 56 01 b9 ff ff 1f 00 ff 15 ?? ?? ?? ?? 48 8b f8 48 89 44 24 50 45 8b f4 c7 44 24 20 40 00 00 00 41 b9 00 30 00 00 45 8b c4 33 d2 48 8b c8 } //3
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*3) >=5
 
}