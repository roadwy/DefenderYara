
rule Ransom_Win32_Zekwacrypt_A{
	meta:
		description = "Ransom:Win32/Zekwacrypt.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {65 6e 63 72 79 70 74 65 64 5f 6c 69 73 74 2e 74 78 74 } //01 00  encrypted_list.txt
		$a_00_1 = {65 6e 63 72 79 70 74 65 64 5f 72 65 61 64 6d 65 2e 74 78 74 } //01 00  encrypted_readme.txt
		$a_80_2 = {64 61 74 61 6b 65 79 2e 74 78 74 } //datakey.txt  01 00 
		$a_80_3 = {52 6f 6f 74 2f 64 65 73 6b 74 6f 70 20 66 69 6c 65 2c 20 77 69 6c 6c 20 70 72 6f 63 65 73 73 20 6c 61 74 65 72 2e 2e 2e } //Root/desktop file, will process later...  01 00 
		$a_80_4 = {45 58 43 45 50 54 49 4f 4e 21 21 21 20 43 61 6e 6e 6f 74 20 65 6e 63 72 79 70 74 20 66 69 6c 65 } //EXCEPTION!!! Cannot encrypt file  00 00 
		$a_00_5 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}