
rule TrojanDownloader_Win32_Banload_AMI{
	meta:
		description = "TrojanDownloader:Win32/Banload.AMI,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 05 00 "
		
	strings :
		$a_00_0 = {57 69 6e 64 6f 77 73 4c 69 76 65 3a 6e 61 6d 65 3d 2a } //05 00 
		$a_00_1 = {50 4f 50 33 20 55 73 65 72 20 4e 61 6d 65 } //01 00 
		$a_00_2 = {2e 6a 65 6d 61 74 6b 64 2e 63 6f 6d 2f 69 6d 67 2f 72 6f 75 6e 64 65 64 2d 62 6f 78 2f 2e 2e 2e 2f } //01 00 
		$a_02_3 = {63 6c 65 61 6e 69 6e 67 2d 64 6f 72 73 65 74 2e 6c 69 6e 75 78 70 6c 2e 65 75 2f 47 50 2f 75 70 6c 6f 61 64 2f 64 72 6f 62 6e 65 2f 90 02 08 2f 73 73 2e 70 68 70 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}