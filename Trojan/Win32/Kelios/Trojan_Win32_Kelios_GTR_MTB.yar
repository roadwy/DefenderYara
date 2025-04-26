
rule Trojan_Win32_Kelios_GTR_MTB{
	meta:
		description = "Trojan:Win32/Kelios.GTR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_03_0 = {40 0f be f5 66 d3 ed c0 f1 81 44 31 a4 0c ?? ?? ?? ?? 4c 8d 84 75 ?? ?? ?? ?? 49 81 e0 ?? ?? ?? ?? 5f 4d 63 e4 40 0f b6 d6 } //10
		$a_03_1 = {33 da 41 66 f7 d0 ff 0c 24 03 ea 66 d3 f8 66 33 44 24 ?? 29 4c 24 ?? 58 58 5a 59 } //10
		$a_03_2 = {66 f7 d2 c1 ea ?? 66 33 d2 8a 8c 15 ?? ?? ?? ?? 36 88 8c 10 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_03_2  & 1)*10) >=10
 
}