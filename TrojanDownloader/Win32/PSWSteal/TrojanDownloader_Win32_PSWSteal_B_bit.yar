
rule TrojanDownloader_Win32_PSWSteal_B_bit{
	meta:
		description = "TrojanDownloader:Win32/PSWSteal.B!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 75 2e 74 6f 2f 50 62 72 54 45 67 } //01 00 
		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 } //00 00 
	condition:
		any of ($a_*)
 
}