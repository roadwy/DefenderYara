
rule Ransom_Win32_FonixCrypt_SK_MTB{
	meta:
		description = "Ransom:Win32/FonixCrypt.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6d 64 2e 65 78 65 20 2f 63 20 76 73 73 61 64 6d 69 6e 20 44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 41 6c 6c 20 2f 51 75 69 65 74 20 26 20 77 6d 69 63 20 73 68 61 64 6f 77 63 6f 70 79 20 64 65 6c 65 74 65 } //1 cmd.exe /c vssadmin Delete Shadows /All /Quiet & wmic shadowcopy delete
		$a_01_1 = {46 6f 6e 69 78 } //1 Fonix
		$a_01_2 = {23 20 48 6f 77 20 54 6f 20 44 65 63 72 79 70 74 20 46 69 6c 65 73 20 23 2e 68 74 61 } //1 # How To Decrypt Files #.hta
		$a_01_3 = {43 6f 70 79 20 43 70 72 69 76 2e 6b 65 79 20 25 61 70 70 64 61 74 61 25 5c 43 70 72 69 76 2e 6b 65 79 } //1 Copy Cpriv.key %appdata%\Cpriv.key
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}