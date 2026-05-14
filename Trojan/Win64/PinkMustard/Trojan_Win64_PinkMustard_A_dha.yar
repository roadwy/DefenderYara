
rule Trojan_Win64_PinkMustard_A_dha{
	meta:
		description = "Trojan:Win64/PinkMustard.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 4b 39 49 4c 4b 53 46 2e 50 72 6f 67 72 61 6d } //2 CK9ILKSF.Program
		$a_01_1 = {61 6d 73 69 2e 64 6c 6c 00 00 00 00 00 00 00 00 55 6e 6b 6e 6f 77 6e 20 65 78 63 65 70 74 69 6f 6e 00 } //1
		$a_01_2 = {53 74 61 72 74 00 00 00 00 00 00 00 22 64 61 74 61 22 3a 00 } //1
		$a_01_3 = {6c 6f 61 64 65 72 2e 76 32 2e 64 6c 6c } //1 loader.v2.dll
		$a_01_4 = {2e 77 6f 72 6b 65 72 73 2e 64 65 76 2f 3b 68 74 74 70 73 3a 2f 2f } //1 .workers.dev/;https://
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=2
 
}