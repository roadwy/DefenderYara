
rule Trojan_Win64_CryptInject_APX_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.APX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {45 8b c1 41 c1 e8 18 48 8b 88 ?? ?? ?? ?? 44 88 04 0a 41 8b d1 ff 05 f7 ae 03 00 49 63 8a 9c 00 00 00 49 8b 82 ?? ?? ?? ?? c1 ea 10 88 14 01 41 8b d1 41 ff 82 9c 00 00 00 48 8b 05 } //2
		$a_03_1 = {44 88 0c 01 41 ff 82 9c 00 00 00 48 8b 05 ?? ?? ?? ?? 8b 88 b4 00 00 00 41 03 8a 1c 01 00 00 41 29 4a 5c 48 8b 0d ?? ?? ?? ?? 41 8b 42 48 35 10 78 11 00 29 41 0c 41 8b 82 08 01 00 00 2d 92 ab 19 00 41 31 82 ?? ?? ?? ?? 49 81 fb e0 79 00 00 0f 8c } //3
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*3) >=5
 
}