
rule Trojan_Win64_Winnti_N_dha{
	meta:
		description = "Trojan:Win64/Winnti.N!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 0f b6 0b ff c2 49 ff c3 80 f1 36 0f b6 c1 c0 e9 04 c0 e0 04 02 c1 41 88 43 ff 3b 13 72 e1 } //1
		$a_01_1 = {b9 03 14 20 00 ff 15 } //1
		$a_01_2 = {b9 04 14 20 00 ff 15 } //1
		$a_01_3 = {41 70 70 69 6e 69 74 36 34 2e 64 6c 6c } //1 Appinit64.dll
		$a_01_4 = {49 6e 73 74 61 6c 6c 00 54 65 73 74 } //1 湉瑳污l敔瑳
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}