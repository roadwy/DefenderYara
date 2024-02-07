
rule Ransom_Win32_MockRans_XT_MTB{
	meta:
		description = "Ransom:Win32/MockRans.XT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {45 78 65 63 75 74 69 6e 67 20 61 20 4d 6f 63 6b 20 52 61 6e 73 6f 6d 77 61 72 65 } //01 00  Executing a Mock Ransomware
		$a_81_1 = {59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //01 00  Your files are encrypted
		$a_81_2 = {50 6c 65 61 73 65 20 70 61 79 20 72 61 6e 73 6f 6d 20 75 73 69 6e 67 20 42 69 74 63 6f 69 6e 20 77 69 74 68 69 6e 20 32 34 68 72 73 20 74 6f 20 67 65 74 20 74 68 65 6d 20 62 61 63 6b 20 73 61 66 65 6c 79 } //01 00  Please pay ransom using Bitcoin within 24hrs to get them back safely
		$a_81_3 = {54 68 69 73 20 69 73 20 61 20 4d 6f 63 6b 20 52 61 6e 73 6f 6d 77 61 72 65 } //01 00  This is a Mock Ransomware
		$a_81_4 = {5c 4d 6f 63 6b 52 61 6e 73 6f 6d 65 77 61 72 65 5c 44 65 62 75 67 5c 4d 6f 63 6b 52 61 6e 73 6f 6d 65 77 61 72 65 2e 70 64 62 } //01 00  \MockRansomeware\Debug\MockRansomeware.pdb
		$a_81_5 = {50 6c 65 61 73 65 5f 52 65 61 64 5f 4d 65 20 40 20 2e 74 78 74 } //00 00  Please_Read_Me @ .txt
		$a_00_6 = {5d 04 00 } //00 8d 
	condition:
		any of ($a_*)
 
}