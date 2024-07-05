
rule Ransom_Win32_Basta_AB_MTB{
	meta:
		description = "Ransom:Win32/Basta.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 66 20 79 6f 75 20 61 72 65 20 72 65 61 64 69 6e 67 20 74 68 69 73 2c 20 69 74 20 6d 65 61 6e 73 20 77 65 20 68 61 76 65 20 65 6e 63 72 79 70 74 65 64 20 79 6f 75 72 20 64 61 74 61 20 61 6e 64 20 74 6f 6f 6b 20 79 6f 75 72 20 66 69 6c 65 73 } //01 00  If you are reading this, it means we have encrypted your data and took your files
		$a_01_1 = {44 4f 20 4e 4f 54 20 50 41 4e 49 43 21 20 59 65 73 2c 20 74 68 69 73 20 69 73 20 62 61 64 20 6e 65 77 73 2c 20 62 75 74 20 77 65 20 77 69 6c 6c 20 68 61 76 65 20 61 20 67 6f 6f 64 20 6f 6e 65 73 20 61 73 20 77 65 6c 6c 2e } //01 00  DO NOT PANIC! Yes, this is bad news, but we will have a good ones as well.
		$a_01_2 = {59 45 53 2c 20 74 68 69 73 20 69 73 20 65 6e 74 69 72 65 6c 79 20 66 69 78 61 62 6c 65 21 } //01 00  YES, this is entirely fixable!
		$a_01_3 = {4f 75 72 20 6e 61 6d 65 20 69 73 20 42 6c 61 63 6b 42 61 73 74 61 20 53 79 6e 64 69 63 61 74 65 } //01 00  Our name is BlackBasta Syndicate
		$a_01_4 = {57 65 20 68 61 76 65 20 79 6f 75 72 20 64 61 74 61 20 61 6e 64 20 65 6e 63 72 79 70 74 65 64 20 79 6f 75 72 20 66 69 6c 65 73 2c 20 62 75 74 20 69 6e 20 6c 65 73 73 20 74 68 61 6e 20 61 6e 20 68 6f 75 72 2c 20 77 65 20 63 61 6e 20 70 75 74 20 74 68 69 6e 67 73 20 62 61 63 6b 20 6f 6e 20 74 72 61 63 6b 3a 20 69 66 20 79 6f 75 20 70 61 79 20 66 6f 72 20 6f 75 72 20 72 65 63 6f 76 65 72 79 20 73 65 72 76 69 63 65 73 2c 20 79 6f 75 20 67 65 74 20 61 20 64 65 63 72 79 70 74 6f 72 2c 20 74 68 65 20 64 61 74 61 20 77 69 6c 6c 20 62 65 20 64 65 6c 65 74 65 64 20 66 72 6f 6d 20 61 6c 6c 20 6f 66 20 6f 75 72 20 73 79 73 74 65 6d 73 20 61 6e 64 20 72 65 74 75 72 6e 65 64 20 74 6f 20 79 6f 75 } //00 00  We have your data and encrypted your files, but in less than an hour, we can put things back on track: if you pay for our recovery services, you get a decryptor, the data will be deleted from all of our systems and returned to you
	condition:
		any of ($a_*)
 
}