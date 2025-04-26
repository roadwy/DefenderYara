
rule Ransom_Win32_Raid_A{
	meta:
		description = "Ransom:Win32/Raid.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_80_0 = {41 4c 4c 20 59 4f 55 52 20 46 49 4c 45 53 20 41 52 45 20 45 4e 43 52 59 50 54 45 44 20 42 59 20 52 41 50 49 44 20 32 2e 30 20 52 41 4e 53 4f 4d 57 41 52 45 } //ALL YOUR FILES ARE ENCRYPTED BY RAPID 2.0 RANSOMWARE  1
		$a_80_1 = {70 75 72 63 68 61 73 65 20 61 20 52 61 70 69 64 20 44 65 63 72 79 70 74 6f 72 } //purchase a Rapid Decryptor  1
		$a_80_2 = {64 65 6c 65 74 65 20 52 61 70 69 64 20 66 72 6f 6d 20 79 6f 75 72 20 50 43 2e } //delete Rapid from your PC.  1
		$a_80_3 = {73 75 70 70 31 64 65 63 72 40 63 6f 63 6b 2e 6c 69 } //supp1decr@cock.li  1
		$a_80_4 = {73 75 70 70 32 64 65 63 72 40 63 6f 63 6b 2e 6c 69 } //supp2decr@cock.li  1
		$a_80_5 = {77 65 20 63 61 6e 20 64 65 63 72 79 70 74 20 6f 6e 6c 79 20 31 20 66 69 6c 65 20 66 6f 72 20 66 72 65 65 } //we can decrypt only 1 file for free  1
		$a_80_6 = {44 6f 6e 74 20 74 72 79 20 74 6f 20 75 73 65 20 74 68 69 72 64 2d 70 61 72 74 79 20 64 65 63 72 79 70 74 6f 72 20 74 6f 6f 6c 73 20 62 65 63 61 75 73 65 20 69 74 20 77 69 6c 6c 20 64 65 73 74 72 6f 79 20 79 6f 75 72 20 66 69 6c 65 73 2e } //Dont try to use third-party decryptor tools because it will destroy your files.  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=5
 
}