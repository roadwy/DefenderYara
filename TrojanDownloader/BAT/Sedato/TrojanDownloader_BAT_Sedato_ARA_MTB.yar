
rule TrojanDownloader_BAT_Sedato_ARA_MTB{
	meta:
		description = "TrojanDownloader:BAT/Sedato.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 65 62 43 6c 69 65 6e 74 } //01 00 
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 41 73 79 6e 63 } //03 00 
		$a_01_2 = {68 74 74 70 73 3a 2f 2f 73 65 65 64 61 75 74 6f 2e 6e 65 74 2f 77 65 62 } //02 00 
		$a_80_3 = {68 74 74 70 73 3a 2f 2f 33 36 30 73 65 65 64 61 75 74 6f 2e 6f 6e 6c 69 6e 65 2f 75 70 64 61 74 65 2f 63 61 70 6e 68 61 74 2e 70 68 70 } //https://360seedauto.online/update/capnhat.php  02 00 
		$a_80_4 = {68 74 74 70 73 3a 2f 2f 33 36 30 73 65 65 64 61 75 74 6f 2e 6f 6e 6c 69 6e 65 2f 75 70 64 61 74 65 2f 53 65 65 64 41 75 74 6f 2e 7a 69 70 } //https://360seedauto.online/update/SeedAuto.zip  01 00 
		$a_80_5 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 } //powershell.exe  01 00 
		$a_01_6 = {50 72 6f 63 65 73 73 53 74 61 72 74 49 6e 66 6f } //01 00 
		$a_01_7 = {73 65 74 5f 43 72 65 61 74 65 4e 6f 57 69 6e 64 6f 77 } //01 00 
		$a_01_8 = {73 65 74 5f 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 } //01 00 
		$a_01_9 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //00 00 
	condition:
		any of ($a_*)
 
}