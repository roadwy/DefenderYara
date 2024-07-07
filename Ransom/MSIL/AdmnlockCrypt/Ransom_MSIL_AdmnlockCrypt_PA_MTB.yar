
rule Ransom_MSIL_AdmnlockCrypt_PA_MTB{
	meta:
		description = "Ransom:MSIL/AdmnlockCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 00 61 00 64 00 6d 00 69 00 6e 00 31 00 } //1 .admin1
		$a_01_1 = {64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 61 00 6c 00 6c 00 20 00 2f 00 71 00 75 00 69 00 65 00 74 00 } //1 delete shadows /all /quiet
		$a_01_2 = {41 00 6c 00 6c 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 61 00 72 00 65 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //1 All files are encrypted
		$a_01_3 = {5c 00 21 00 21 00 21 00 52 00 65 00 63 00 6f 00 76 00 65 00 72 00 79 00 20 00 46 00 69 00 6c 00 65 00 2e 00 74 00 78 00 74 00 } //1 \!!!Recovery File.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}