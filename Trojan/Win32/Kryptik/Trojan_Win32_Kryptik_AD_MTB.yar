
rule Trojan_Win32_Kryptik_AD_MTB{
	meta:
		description = "Trojan:Win32/Kryptik.AD!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 06 83 f1 cd 89 4d e4 2d b9 da 65 00 a9 4b 00 00 00 74 03 89 45 d4 3d d7 e7 49 ab 0f 85 } //1
		$a_01_1 = {8b c1 81 eb 00 80 41 98 89 45 e8 89 5d b8 8b 7d 0c 33 df 8b cb 3b cb 74 0d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}