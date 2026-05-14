
rule Ransom_Linux_Weaxor_C_MTB{
	meta:
		description = "Ransom:Linux/Weaxor.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {2f 62 69 77 65 61 78 2e 70 68 70 } //1 /biweax.php
		$a_01_1 = {72 78 2e 74 78 74 } //1 rx.txt
		$a_01_2 = {52 45 43 4f 56 45 52 59 20 49 4e 46 4f 52 4d 41 54 49 4f 4e 2e 74 78 74 } //1 RECOVERY INFORMATION.txt
		$a_01_3 = {62 6c 6f 63 6b 20 64 65 76 69 63 65 20 68 65 61 64 65 72 20 66 69 6c 65 20 69 73 20 65 78 69 73 74 73 2c 20 70 6c 65 61 73 65 20 72 65 6e 61 6d 65 20 61 6e 64 20 62 61 63 6b 75 70 20 69 74 20 61 6e 64 20 72 65 2d 72 75 6e 20 61 67 61 69 6e 2e } //1 block device header file is exists, please rename and backup it and re-run again.
		$a_01_4 = {64 61 74 61 68 65 6c 70 65 72 40 63 79 62 65 72 66 65 61 72 2e 63 6f 6d } //1 datahelper@cyberfear.com
		$a_01_5 = {49 20 63 61 6e 74 20 6b 69 6c 6c 20 70 72 6f 63 65 73 73 20 77 69 74 68 20 69 64 } //1 I cant kill process with id
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}