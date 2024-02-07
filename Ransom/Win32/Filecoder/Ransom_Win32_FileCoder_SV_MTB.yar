
rule Ransom_Win32_FileCoder_SV_MTB{
	meta:
		description = "Ransom:Win32/FileCoder.SV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {49 66 20 59 6f 75 20 77 61 6e 74 20 64 65 63 72 79 70 74 20 66 69 6c 65 73 20 70 6c 65 61 73 65 20 63 6f 6e 74 61 63 74 20 75 73 20 6f 6e 20 6a 61 62 62 65 72 3a } //01 00  If You want decrypt files please contact us on jabber:
		$a_81_1 = {70 61 79 6d 65 70 6c 65 61 73 65 40 73 6a 2e 6d 73 20 59 6f 75 72 73 20 50 49 4e 20 69 73 3a } //01 00  paymeplease@sj.ms Yours PIN is:
		$a_81_2 = {6a 75 73 74 66 69 6c 65 2e 74 78 74 } //01 00  justfile.txt
		$a_81_3 = {73 79 73 74 6d 73 2e 65 78 65 } //00 00  systms.exe
		$a_00_4 = {78 2a } //01 00  x*
	condition:
		any of ($a_*)
 
}
rule Ransom_Win32_FileCoder_SV_MTB_2{
	meta:
		description = "Ransom:Win32/FileCoder.SV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4f 6f 70 73 2c 20 61 6c 6c 20 79 6f 75 72 20 64 6f 63 75 6d 65 6e 74 73 2c 20 70 68 6f 74 6f 73 2c 20 76 69 64 65 6f 73 20 61 6e 64 20 64 61 74 61 62 61 73 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 20 62 79 20 74 68 65 20 58 79 20 52 61 6e 73 6f 6d 77 61 72 65 } //01 00  Oops, all your documents, photos, videos and databases are encrypted by the Xy Ransomware
		$a_01_1 = {49 66 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 67 65 74 20 74 68 65 6d 20 62 61 63 6b 2c 20 70 61 79 20 35 30 30 20 24 20 69 6e 20 42 69 74 63 6f 69 6e 20 74 6f 20 74 68 65 20 61 64 72 65 73 73 20 33 4e 6f 78 56 67 79 4f 33 6e 47 42 68 69 77 71 62 38 66 68 79 4d 55 50 50 76 } //01 00  If you want to get them back, pay 500 $ in Bitcoin to the adress 3NoxVgyO3nGBhiwqb8fhyMUPPv
		$a_01_2 = {59 6f 75 20 68 61 76 65 20 37 32 20 68 6f 75 72 73 20 74 6f 20 70 61 79 2c 20 74 68 65 6e 20 41 4c 4c 20 79 6f 75 72 20 66 69 6c 65 73 20 77 69 6c 6c 20 62 65 20 67 6f 6e 65 2e 40 } //01 00  You have 72 hours to pay, then ALL your files will be gone.@
		$a_01_3 = {45 3a 5c 52 61 6e 73 6f 6d 77 61 72 65 5c 61 5c 61 5c 6f 62 6a 5c 44 65 62 75 67 5c 61 2e 70 64 62 } //00 00  E:\Ransomware\a\a\obj\Debug\a.pdb
	condition:
		any of ($a_*)
 
}