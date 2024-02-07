
rule Ransom_Win64_Henasome_P_MTB{
	meta:
		description = "Ransom:Win64/Henasome.P!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 77 69 74 68 20 61 20 72 61 6e 64 6f 6d 20 6b 65 79 20 61 6e 64 20 6e 6f 20 64 65 63 72 79 70 74 69 6f 6e 20 74 6f 6f 6c 20 63 61 6e 20 73 61 76 65 20 74 68 65 6d } //01 00  All your files have been encrypted with a random key and no decryption tool can save them
		$a_81_1 = {69 61 6d 69 6e 66 65 63 74 65 64 2e 73 61 63 40 65 6c 75 64 65 2e 69 } //01 00  iaminfected.sac@elude.i
		$a_81_2 = {57 65 20 61 72 65 20 6e 6f 74 20 73 63 61 6d 6d 65 72 73 2c 20 79 6f 75 72 20 66 69 6c 65 73 20 77 69 6c 6c 20 62 65 20 75 6e 6c 6f 63 6b 65 64 20 69 66 20 79 6f 75 20 70 61 79 } //01 00  We are not scammers, your files will be unlocked if you pay
		$a_81_3 = {49 66 20 79 6f 75 20 77 6f 75 6c 64 20 6c 69 6b 65 20 74 6f 20 72 65 67 61 69 6e 20 61 63 63 65 73 73 20 74 6f 20 79 6f 75 72 20 66 69 6c 65 73 2c 20 70 6c 65 61 73 65 20 6d 61 6b 65 20 61 20 24 31 30 30 20 64 6f 6e 61 74 69 6f 6e 20 74 6f 20 53 69 6c 69 63 6f 6e 20 56 65 6e 6f 6d } //01 00  If you would like to regain access to your files, please make a $100 donation to Silicon Venom
		$a_81_4 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 41 6c 6c 20 2f 51 75 69 65 74 } //01 00  vssadmin.exe Delete Shadows /All /Quiet
		$a_81_5 = {3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 63 6d 64 6b 65 79 2e 62 61 74 } //01 00  :\ProgramData\cmdkey.bat
		$a_81_6 = {3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 63 6d 64 6b 65 79 2e 65 78 65 } //00 00  :\Windows\System32\cmdkey.exe
	condition:
		any of ($a_*)
 
}