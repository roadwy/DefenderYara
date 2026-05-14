
rule Ransom_Win32_Lockbit_AMTB{
	meta:
		description = "Ransom:Win32/Lockbit!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {24 66 69 6c 65 50 61 74 68 2e 6c 6f 63 6b 62 69 74 } //$filePath.lockbit  1
		$a_80_1 = {45 6e 63 72 79 70 74 2e 70 73 31 } //Encrypt.ps1  1
		$a_80_2 = {57 72 69 74 65 20 74 68 65 20 65 6e 63 72 79 70 74 65 64 20 64 61 74 61 20 74 6f 20 61 20 6e 65 77 20 66 69 6c 65 20 77 69 74 68 20 61 20 2e 65 6e 63 72 20 65 78 74 65 6e 73 69 6f 6e } //Write the encrypted data to a new file with a .encr extension  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}