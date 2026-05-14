
rule Ransom_MSIL_XretCrypt_PA_MTB{
	meta:
		description = "Ransom:MSIL/XretCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 00 59 00 53 00 54 00 45 00 4d 00 20 00 48 00 41 00 43 00 4b 00 45 00 44 00 20 00 42 00 59 00 20 00 58 00 52 00 45 00 54 00 } //3 SYSTEM HACKED BY XRET
		$a_01_1 = {41 00 6c 00 6c 00 20 00 69 00 6e 00 66 00 6f 00 72 00 6d 00 61 00 74 00 69 00 6f 00 6e 00 20 00 68 00 61 00 73 00 20 00 62 00 65 00 65 00 6e 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //1 All information has been encrypted
		$a_01_2 = {76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 20 00 44 00 65 00 6c 00 65 00 74 00 65 00 20 00 53 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 41 00 6c 00 6c 00 20 00 2f 00 51 00 75 00 69 00 65 00 74 00 } //1 vssadmin Delete Shadows /All /Quiet
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}