
rule Trojan_Win32_LummaC_RZ_MTB{
	meta:
		description = "Trojan:Win32/LummaC.RZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {89 c8 c1 e0 02 29 c4 89 e7 8b 73 08 fc f3 a5 ff 13 } //2
		$a_01_1 = {6d 61 69 6e 2e 50 5a 7a 64 49 56 41 6e 6d 62 2e 66 75 6e 63 31 } //1 main.PZzdIVAnmb.func1
		$a_01_2 = {6d 61 69 6e 2e 57 49 4b 6a 6a 67 41 67 4f 41 2e 66 75 6e 63 31 } //1 main.WIKjjgAgOA.func1
		$a_01_3 = {6d 61 69 6e 2e 76 70 62 42 70 4b 70 73 74 67 2e 64 65 66 65 72 77 72 61 70 32 } //1 main.vpbBpKpstg.deferwrap2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}