
rule Ransom_Win32_RookCrypt_PA_MTB{
	meta:
		description = "Ransom:Win32/RookCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 00 63 00 20 00 76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 2e 00 65 00 78 00 65 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 61 00 6c 00 6c 00 20 00 2f 00 71 00 75 00 69 00 65 00 74 00 } //1 /c vssadmin.exe delete shadows /all /quiet
		$a_01_1 = {59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //1 Your files are encrypted
		$a_01_2 = {5c 00 48 00 6f 00 77 00 54 00 6f 00 52 00 65 00 73 00 74 00 6f 00 72 00 65 00 59 00 6f 00 75 00 72 00 46 00 69 00 6c 00 65 00 73 00 2e 00 74 00 78 00 74 00 } //1 \HowToRestoreYourFiles.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}