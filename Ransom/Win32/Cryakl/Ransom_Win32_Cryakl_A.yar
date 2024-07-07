
rule Ransom_Win32_Cryakl_A{
	meta:
		description = "Ransom:Win32/Cryakl.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //2 vssadmin delete shadows /all /quiet
		$a_01_1 = {77 72 69 74 65 20 79 6f 75 20 63 6f 75 6e 74 72 79 20 74 6f 20 64 6f 72 69 73 70 61 63 6b 6d 61 6e 40 74 75 74 61 2e 69 6f } //2 write you country to dorispackman@tuta.io
		$a_01_2 = {61 73 73 68 6f 6c 65 } //1 asshole
		$a_01_3 = {50 61 79 20 66 6f 72 20 64 65 63 72 79 70 74 } //1 Pay for decrypt
		$a_01_4 = {7b 45 4e 43 52 59 50 54 45 4e 44 45 44 7d } //1 {ENCRYPTENDED}
		$a_01_5 = {7b 45 4e 43 52 59 50 54 53 54 41 52 54 7d } //1 {ENCRYPTSTART}
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}