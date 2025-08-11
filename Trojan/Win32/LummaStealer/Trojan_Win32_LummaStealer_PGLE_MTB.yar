
rule Trojan_Win32_LummaStealer_PGLE_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.PGLE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 74 0c ?? 89 c7 83 e7 ?? 89 ca 81 f2 ?? ?? ?? ?? 01 fa 89 d7 f7 d7 21 f7 89 d3 31 f3 01 f3 29 fb 21 f2 f7 d2 21 da 89 14 24 8b 14 24 80 c2 9c 88 54 0c ?? 41 83 c0 ?? 83 f9 ?? 75 } //5
		$a_03_1 = {89 fb 09 f3 21 d6 09 ce 81 f6 ?? ?? ?? ?? 89 f9 09 d1 21 f1 21 d3 89 da f7 d2 8d 14 53 42 21 ca 89 55 ?? 8b 4d ?? 80 c1 ?? 88 8c 38 ?? ?? ?? ?? 47 81 ff ?? ?? ?? ?? 75 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=5
 
}