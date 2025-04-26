
rule Trojan_Win32_Sadacal_A{
	meta:
		description = "Trojan:Win32/Sadacal.A,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0b 00 06 00 00 "
		
	strings :
		$a_03_0 = {50 56 6a 13 ff 75 ?? c7 45 ?? 0a 00 00 00 ff 15 } //5
		$a_03_1 = {c6 45 d4 5c 47 e8 ?? ?? ?? ?? 6a 1a 99 59 f7 f9 80 c2 61 88 54 3d d4 47 83 ff 0b } //5
		$a_01_2 = {74 61 73 6b 2f 61 63 63 } //1 task/acc
		$a_01_3 = {74 61 73 6b 2f 66 69 6c 65 73 } //1 task/files
		$a_01_4 = {74 61 73 6b 2f 63 6f 64 65 } //1 task/code
		$a_01_5 = {70 61 79 6d 65 6e 74 00 75 70 6c 6f 61 64 00 00 70 72 6f 63 65 73 73 00 73 74 61 74 } //3
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*3) >=11
 
}