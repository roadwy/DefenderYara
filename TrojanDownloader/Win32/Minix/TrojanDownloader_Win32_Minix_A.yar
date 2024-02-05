
rule TrojanDownloader_Win32_Minix_A{
	meta:
		description = "TrojanDownloader:Win32/Minix.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_13_0 = {78 69 78 69 68 61 63 68 65 2e 69 6e 66 6f 3a 31 33 35 35 2f 73 6f 66 74 2f 90 02 0a 2e 65 78 65 00 2f 53 49 4c 45 4e 54 00 67 65 74 90 00 00 } //00 5d 
	condition:
		any of ($a_*)
 
}