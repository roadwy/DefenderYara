
rule Ransom_Win32_Ergop_B{
	meta:
		description = "Ransom:Win32/Ergop.B,SIGNATURE_TYPE_PEHSTR,64 00 64 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 ec 34 53 56 57 bf 88 60 02 03 57 e8 ca bc ff ff 59 3d b3 01 00 00 76 17 81 7d d8 9b 4b 08 00 74 0e 81 7d d8 04 11 00 00 74 05 e8 } //100
		$a_01_1 = {55 8b ec 83 ec 3c 53 56 57 68 28 e8 02 03 e8 6d 03 ff ff 33 db 59 3d b3 01 00 00 0f 86 2b 01 00 00 81 7d d0 9b 4b 08 00 0f 84 1e 01 00 00 81 7d d0 04 11 00 00 0f 84 11 01 00 00 e8 00 ff ff ff } //100
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100) >=100
 
}
rule Ransom_Win32_Ergop_B_2{
	meta:
		description = "Ransom:Win32/Ergop.B,SIGNATURE_TYPE_PEHSTR,06 00 06 00 08 00 00 "
		
	strings :
		$a_01_0 = {00 71 66 6a 67 6d 66 67 6d 6b 6a 2e 74 6d 70 00 } //3
		$a_01_1 = {00 72 73 61 5f 70 72 69 76 5f 74 65 73 74 69 6e 67 2e 74 78 74 00 } //1
		$a_01_2 = {00 5c 77 61 6c 6c 2e 6a 70 67 00 } //1
		$a_01_3 = {73 71 6c 00 6f 75 74 6c 6f 6f 6b 00 73 73 6d 73 } //1 煳l畯汴潯k獳獭
		$a_01_4 = {53 69 6e 67 6c 65 20 62 6c 6f 63 6b 20 6d 73 67 } //1 Single block msg
		$a_01_5 = {5c 55 73 65 72 73 5c 61 31 31 63 68 65 6d 69 73 74 5c 44 6f 63 75 6d 65 6e 74 73 5c } //2 \Users\a11chemist\Documents\
		$a_01_6 = {5c 61 31 33 6c 6f 63 6b 5f 66 69 6e 61 6c 2e 70 64 62 00 } //2
		$a_01_7 = {44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 41 6c 6c 20 2f 51 75 69 65 74 } //1 Delete Shadows /All /Quiet
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*1) >=6
 
}