
rule Ransom_MSIL_FileCryptor_PG_MTB{
	meta:
		description = "Ransom:MSIL/FileCryptor.PG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 00 78 00 78 00 78 00 } //01 00  .xxx
		$a_01_1 = {5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 72 00 65 00 61 00 64 00 6d 00 65 00 2e 00 74 00 78 00 74 00 } //01 00  \Desktop\readme.txt
		$a_01_2 = {46 00 69 00 6c 00 65 00 73 00 20 00 68 00 61 00 76 00 65 00 20 00 62 00 65 00 65 00 6e 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 21 00 } //00 00  Files have been encrypted!
	condition:
		any of ($a_*)
 
}
rule Ransom_MSIL_FileCryptor_PG_MTB_2{
	meta:
		description = "Ransom:MSIL/FileCryptor.PG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {3c 52 61 6e 73 6f 6d 5f 4e 6f 74 65 5f 4c 6f 61 64 3e 62 } //01 00  <Ransom_Note_Load>b
		$a_01_1 = {64 00 6f 00 20 00 6e 00 6f 00 74 00 20 00 72 00 65 00 73 00 74 00 61 00 72 00 74 00 20 00 79 00 6f 00 75 00 72 00 20 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 20 00 6f 00 72 00 20 00 65 00 6c 00 73 00 65 00 20 00 69 00 74 00 20 00 69 00 73 00 20 00 64 00 65 00 73 00 74 00 72 00 6f 00 79 00 65 00 64 00 21 00 21 00 21 00 21 00 21 00 21 00 21 00 21 00 21 00 21 00 21 00 21 00 21 00 } //01 00  do not restart your computer or else it is destroyed!!!!!!!!!!!!!
		$a_01_2 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 54 00 61 00 73 00 6b 00 6d 00 67 00 72 00 } //01 00  DisableTaskmgr
		$a_01_3 = {79 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 21 } //01 00  your files are encrypted!
		$a_01_4 = {49 00 6e 00 73 00 74 00 61 00 6e 00 74 00 52 00 61 00 6e 00 73 00 6f 00 6d 00 40 00 } //01 00  InstantRansom@
		$a_01_5 = {49 00 6e 00 73 00 74 00 61 00 6e 00 74 00 20 00 52 00 61 00 6e 00 73 00 6f 00 6d 00 77 00 61 00 72 00 65 00 } //00 00  Instant Ransomware
		$a_00_6 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}