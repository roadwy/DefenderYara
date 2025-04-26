
rule Trojan_BAT_NjRat_NECE_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NECE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 05 00 00 "
		
	strings :
		$a_01_0 = {38 61 31 39 39 35 35 66 2d 37 32 31 61 2d 34 31 31 31 2d 39 61 37 61 2d 34 32 36 66 34 63 62 64 64 66 62 36 } //5 8a19955f-721a-4111-9a7a-426f4cbddfb6
		$a_01_1 = {73 6f 63 69 61 6c 20 6d 65 64 69 61 20 6f 70 74 69 6d 69 7a 61 74 69 6f 6e 2e 65 78 65 } //2 social media optimization.exe
		$a_01_2 = {45 00 76 00 61 00 6c 00 75 00 61 00 74 00 69 00 6f 00 6e 00 20 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 } //2 Evaluation Version
		$a_01_3 = {53 79 73 74 65 6d 2e 52 65 66 6c 65 63 74 69 6f 6e } //1 System.Reflection
		$a_01_4 = {46 6f 72 6d 31 5f 4c 6f 61 64 } //1 Form1_Load
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=11
 
}