
rule Trojan_Win32_Rozena_RK_MTB{
	meta:
		description = "Trojan:Win32/Rozena.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 30 00 00 68 30 c5 04 00 6a 00 ff 54 24 34 } //2
		$a_01_1 = {8b 43 3c 89 45 f4 8b 43 38 05 08 c4 04 00 89 45 f0 8b 7d f0 8b 75 f4 b9 28 01 00 00 f3 a4 } //2
		$a_01_2 = {73 68 65 6c 6c 63 6f 64 65 6c 6f 64 65 72 2e 70 64 62 } //1 shellcodeloder.pdb
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}