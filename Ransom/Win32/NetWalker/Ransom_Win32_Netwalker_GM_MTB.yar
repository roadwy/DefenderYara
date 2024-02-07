
rule Ransom_Win32_Netwalker_GM_MTB{
	meta:
		description = "Ransom:Win32/Netwalker.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 07 00 00 02 00 "
		
	strings :
		$a_00_0 = {4e 65 74 77 61 6c 6b 65 72 20 44 65 63 72 79 70 74 65 72 } //02 00  Netwalker Decrypter
		$a_00_1 = {44 65 6c 65 74 65 20 63 72 79 70 74 65 72 20 2a 2e 74 78 74 20 66 69 6c 65 73 } //05 00  Delete crypter *.txt files
		$a_00_2 = {6e 65 74 77 61 6c 6b 65 72 } //05 00  netwalker
		$a_00_3 = {42 72 6f 77 73 65 20 66 6f 6c 64 65 72 20 6f 72 20 64 69 73 6b } //02 00  Browse folder or disk
		$a_00_4 = {44 65 6c 65 74 65 20 63 72 79 70 74 65 72 20 6e 6f 74 65 20 66 69 6c 65 73 } //05 00  Delete crypter note files
		$a_00_5 = {65 78 70 61 6e 64 20 33 32 2d 62 79 74 65 20 6b 65 78 70 61 6e 64 20 31 36 2d 62 79 74 65 20 6b } //05 00  expand 32-byte kexpand 16-byte k
		$a_01_6 = {46 00 69 00 6c 00 65 00 20 00 64 00 65 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //00 00  File decrypted
	condition:
		any of ($a_*)
 
}