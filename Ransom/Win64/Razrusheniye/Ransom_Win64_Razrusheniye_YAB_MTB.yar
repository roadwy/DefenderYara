
rule Ransom_Win64_Razrusheniye_YAB_MTB{
	meta:
		description = "Ransom:Win64/Razrusheniye.YAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {78 6d 62 2e 70 79 74 68 6f 6e 61 6e 79 77 68 65 72 65 2e 63 6f 6d } //1 xmb.pythonanywhere.com
		$a_01_1 = {52 45 41 44 4d 45 2e 74 78 74 } //1 README.txt
		$a_01_2 = {76 69 63 74 69 6d 20 6f 66 20 74 68 65 20 72 61 7a 72 75 73 68 65 6e 69 79 65 20 72 61 6e 73 6f 6d 77 61 72 65 } //10 victim of the razrusheniye ransomware
		$a_01_3 = {66 69 6c 65 20 77 69 74 68 20 74 68 65 20 2e 72 61 7a 20 65 78 74 65 6e 73 69 6f 6e } //1 file with the .raz extension
		$a_01_4 = {6d 6f 64 69 66 79 20 65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 } //1 modify encrypted files
		$a_01_5 = {64 65 63 72 79 70 74 20 74 68 65 73 65 20 66 69 6c 65 73 } //1 decrypt these files
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}