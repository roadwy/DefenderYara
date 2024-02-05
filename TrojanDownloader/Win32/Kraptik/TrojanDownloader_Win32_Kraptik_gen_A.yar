
rule TrojanDownloader_Win32_Kraptik_gen_A{
	meta:
		description = "TrojanDownloader:Win32/Kraptik.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {68 eb ca ee 80 ff 15 90 01 02 40 00 90 00 } //01 00 
		$a_02_1 = {68 6d b3 29 d9 ff 15 90 01 02 40 00 90 00 } //01 00 
		$a_02_2 = {68 5e 1e c0 8f 53 68 7c 23 3a bf 52 68 00 00 00 00 ff 15 90 01 02 40 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}