
rule Trojan_Win64_StealC_NRA_MTB{
	meta:
		description = "Trojan:Win64/StealC.NRA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_81_0 = {30 63 7a 4f 58 42 4a 6a 63 6e 58 63 69 65 4f 55 43 36 36 35 45 64 75 4b 4d 74 62 71 74 } //1 0czOXBJjcnXcieOUC665EduKMtbqt
		$a_81_1 = {30 6f 62 78 57 43 51 46 61 4d 48 73 78 67 48 74 61 50 47 69 32 67 78 54 31 64 72 39 } //1 0obxWCQFaMHsxgHtaPGi2gxT1dr9
		$a_81_2 = {32 53 77 61 64 6e 73 6f 79 6b 56 6e 41 75 32 43 77 4f 66 39 52 70 6d 48 } //1 2SwadnsoykVnAu2CwOf9RpmH
		$a_81_3 = {34 76 49 36 43 50 7a 41 4f 66 68 41 6e 46 57 34 42 74 33 50 36 49 63 71 55 79 51 4c } //1 4vI6CPzAOfhAnFW4Bt3P6IcqUyQL
		$a_03_4 = {49 8b ce 8b 42 04 48 03 c1 43 8b 8c 3b ?? ?? ?? ?? 48 d3 e8 48 83 c8 01 48 0f bd c8 43 8b 84 3b ?? ?? ?? ?? ff c8 3b c1 0f 42 } //3
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_03_4  & 1)*3) >=7
 
}