
rule Ransom_Win32_SporaCrypt_PAD_MTB{
	meta:
		description = "Ransom:Win32/SporaCrypt.PAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 00 65 00 61 00 64 00 4d 00 65 00 5f 00 4e 00 6f 00 77 00 } //01 00  ReadMe_Now
		$a_01_1 = {41 00 6c 00 6c 00 20 00 59 00 6f 00 75 00 72 00 20 00 46 00 69 00 6c 00 65 00 73 00 20 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //01 00  All Your Files Encrypted
		$a_01_2 = {73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 73 63 20 6d 69 6e 75 74 65 20 2f 6d 6f } //01 00  schtasks /create /sc minute /mo
		$a_01_3 = {76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 2e 00 65 00 78 00 65 00 20 00 44 00 65 00 6c 00 65 00 74 00 65 00 20 00 53 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 41 00 6c 00 6c 00 20 00 2f 00 51 00 75 00 69 00 65 00 74 00 } //00 00  vssadmin.exe Delete Shadows /All /Quiet
		$a_00_4 = {5d 04 00 } //00 5b 
	condition:
		any of ($a_*)
 
}