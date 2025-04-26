
rule Trojan_Win64_ShellcodeRunner_HNB_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.HNB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {46 61 69 6c 65 64 20 69 6e 20 63 68 61 6e 67 69 6e 67 20 70 72 6f 74 65 63 74 69 6f 6e 20 28 25 75 29 [0-10] 46 61 69 6c 65 64 20 69 6e 20 63 68 61 6e 67 69 6e 67 20 70 72 6f 74 65 63 74 69 6f 6e 20 62 61 63 6b 20 28 25 75 29 } //2
		$a_01_1 = {46 43 2d 34 38 2d 38 33 2d 45 34 2d 46 30 2d 45 38 } //1 FC-48-83-E4-F0-E8
		$a_01_2 = {43 30 2d 30 30 2d 30 30 2d 30 30 2d 34 31 2d 35 31 } //1 C0-00-00-00-41-51
		$a_01_3 = {4e 74 43 72 65 61 74 65 54 68 72 65 61 64 45 78 20 48 6f 6f 6b 65 64 } //1 NtCreateThreadEx Hooked
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}