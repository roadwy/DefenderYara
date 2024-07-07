
rule Trojan_Win32_FlyStudio_DU_MTB{
	meta:
		description = "Trojan:Win32/FlyStudio.DU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {f6 d1 66 85 d1 32 d9 89 04 0c 66 f7 d9 66 0f ab e9 66 81 e9 47 46 81 ed 04 00 00 00 8b 4c 25 00 f7 c4 b2 4d 81 04 f5 33 cb 66 81 ff 93 72 66 85 f1 f7 d9 3d 7e 2f 08 66 81 f1 a3 7b 0d 58 e9 } //1
		$a_01_1 = {8b 4c 25 00 8d ad 04 00 00 00 33 cb f7 d9 85 e3 f5 81 c1 91 7b 69 50 f8 f5 f9 d1 c9 41 f5 33 d9 03 f1 e9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}