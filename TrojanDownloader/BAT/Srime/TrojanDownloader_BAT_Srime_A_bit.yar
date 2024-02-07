
rule TrojanDownloader_BAT_Srime_A_bit{
	meta:
		description = "TrojanDownloader:BAT/Srime.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 6d 00 61 00 6e 00 33 00 33 00 2e 00 72 00 75 00 2f 00 90 02 30 2e 00 6a 00 70 00 67 00 90 00 } //01 00 
		$a_01_1 = {26 00 74 00 79 00 70 00 65 00 3d 00 61 00 64 00 64 00 6c 00 6f 00 67 00 26 00 74 00 65 00 78 00 74 00 3d 00 } //01 00  &type=addlog&text=
		$a_01_2 = {5c 00 74 00 61 00 73 00 6b 00 68 00 6f 00 73 00 74 00 65 00 78 00 2e 00 65 00 78 00 65 00 } //01 00  \taskhostex.exe
		$a_01_3 = {2f 00 74 00 61 00 73 00 6b 00 68 00 6f 00 73 00 74 00 65 00 77 00 2e 00 65 00 78 00 65 00 } //00 00  /taskhostew.exe
	condition:
		any of ($a_*)
 
}