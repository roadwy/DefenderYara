
rule Ransom_Win64_FileCoder_AYE_MTB{
	meta:
		description = "Ransom:Win64/FileCoder.AYE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 6f 77 20 74 6f 20 72 65 73 74 6f 72 65 20 79 6f 75 72 20 66 69 6c 65 73 2e 74 78 74 } //2 How to restore your files.txt
		$a_01_1 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 64 75 65 20 74 6f 20 75 6e 61 75 74 68 6f 72 69 7a 65 64 20 75 73 65 20 6f 66 20 6f 75 72 20 69 74 65 6d 2e } //2 Your files have been encrypted due to unauthorized use of our item.
		$a_01_2 = {54 6f 20 72 65 73 74 6f 72 65 20 79 6f 75 72 20 66 69 6c 65 73 2c 20 79 6f 75 20 6d 75 73 74 20 62 75 79 20 61 20 73 70 65 63 69 61 6c 20 70 72 6f 67 72 61 6d 2c 20 74 68 69 73 20 70 72 6f 67 72 61 6d 20 62 65 6c 6f 6e 67 20 74 6f 20 75 73 20 61 6c 6f 6e 65 2e } //1 To restore your files, you must buy a special program, this program belong to us alone.
		$a_01_3 = {74 6f 6e 67 66 61 6b 65 2e 64 6c 6c } //1 tongfake.dll
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}