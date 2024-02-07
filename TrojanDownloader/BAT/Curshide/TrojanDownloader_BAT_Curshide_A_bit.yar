
rule TrojanDownloader_BAT_Curshide_A_bit{
	meta:
		description = "TrojanDownloader:BAT/Curshide.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6e 00 65 00 74 00 73 00 68 00 20 00 61 00 64 00 76 00 66 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 20 00 73 00 65 00 74 00 20 00 61 00 6c 00 6c 00 70 00 72 00 6f 00 66 00 69 00 6c 00 65 00 73 00 20 00 73 00 74 00 61 00 74 00 65 00 } //01 00  netsh advfirewall set allprofiles state
		$a_01_1 = {53 00 65 00 72 00 76 00 65 00 72 00 20 00 3d 00 20 00 63 00 61 00 6e 00 6e 00 6f 00 74 00 6a 00 61 00 76 00 61 00 63 00 2e 00 63 00 6f 00 6d 00 3b 00 20 00 44 00 61 00 74 00 61 00 62 00 61 00 73 00 65 00 20 00 3d 00 20 00 63 00 61 00 6e 00 6e 00 6f 00 74 00 6a 00 61 00 76 00 61 00 63 00 5f 00 63 00 6f 00 6d 00 5f 00 50 00 54 00 45 00 3b 00 } //01 00  Server = cannotjavac.com; Database = cannotjavac_com_PTE;
		$a_01_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 63 00 61 00 6e 00 6e 00 6f 00 74 00 6a 00 61 00 76 00 61 00 63 00 2e 00 63 00 6f 00 6d 00 2f 00 70 00 74 00 65 00 2f 00 6c 00 69 00 6e 00 6b 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 63 00 72 00 75 00 73 00 68 00 2e 00 74 00 78 00 74 00 } //00 00  http://cannotjavac.com/pte/linkwindowscrush.txt
	condition:
		any of ($a_*)
 
}