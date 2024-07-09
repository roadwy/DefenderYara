
rule Trojan_Win64_CryptInject_QM_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.QM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {34 e5 88 01 48 8d 49 01 0f b6 ?? 84 c0 75 } //1
		$a_03_1 = {80 34 30 e5 48 ff c0 48 3d ?? ?? ?? ?? 7c } //1
		$a_03_2 = {80 32 e5 48 8d 52 ?? ff c1 83 f9 ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}