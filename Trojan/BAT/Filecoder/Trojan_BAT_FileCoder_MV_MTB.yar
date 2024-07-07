
rule Trojan_BAT_FileCoder_MV_MTB{
	meta:
		description = "Trojan:BAT/FileCoder.MV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 08 00 00 "
		
	strings :
		$a_00_0 = {66 61 6b 65 63 72 79 2e 70 64 62 } //10 fakecry.pdb
		$a_80_1 = {62 69 74 63 6f 69 6e } //bitcoin  1
		$a_01_2 = {79 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 68 00 61 00 76 00 65 00 20 00 62 00 65 00 65 00 6e 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //1 your files have been encrypted
		$a_00_3 = {52 61 6e 73 6f 6d 77 61 72 65 2e 70 64 62 } //10 Ransomware.pdb
		$a_00_4 = {43 61 6c 63 75 6c 61 74 6f 72 2e 65 78 65 } //10 Calculator.exe
		$a_00_5 = {45 6e 63 72 79 70 74 46 69 6c 65 } //1 EncryptFile
		$a_00_6 = {70 00 61 00 79 00 6d 00 65 00 6e 00 74 00 20 00 63 00 6f 00 6e 00 66 00 69 00 72 00 6d 00 61 00 74 00 69 00 6f 00 6e 00 } //1 payment confirmation
		$a_00_7 = {70 72 6f 6a 65 63 74 6d 61 72 73 2e 65 78 65 } //10 projectmars.exe
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*10+(#a_00_4  & 1)*10+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*10) >=12
 
}