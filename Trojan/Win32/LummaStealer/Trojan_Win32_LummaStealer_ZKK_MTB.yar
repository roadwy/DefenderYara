
rule Trojan_Win32_LummaStealer_ZKK_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.ZKK!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 ff c6 48 89 7c 24 38 48 89 7c 24 30 c7 44 24 28 05 00 00 00 48 8d 45 0f 48 89 44 24 20 45 8b cc 4c 8d 45 93 33 d2 8b 4d b7 e8 2f d9 ff ff 44 8b f0 85 c0 0f 84 1b 01 00 00 48 89 7c 24 20 4c 8d 4d 97 44 8b c0 48 8d 55 0f 4c 8b 65 e7 49 8b cc ff 15 33 00 01 00 85 c0 0f 84 ee 00 00 00 8b d6 2b 55 bf 03 53 08 89 53 04 44 39 75 97 0f 82 e1 00 00 00 80 7d 8f 0a 75 3e b8 0d 00 00 00 66 89 45 8f 48 89 7c 24 20 4c 8d 4d 97 44 8d 40 f4 48 8d 55 8f 49 8b cc ff 15 ed ff 00 00 85 c0 0f 84 a8 00 00 00 83 7d 97 01 0f 82 a6 00 00 00 ff 43 08 ff 43 04 8b 53 04 48 3b 75 9f 0f 83 93 00 00 00 4c 8b 55 a7 4c 8b 4d ef 8b 4d bb } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}