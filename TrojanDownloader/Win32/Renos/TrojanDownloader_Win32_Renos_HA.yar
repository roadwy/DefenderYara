
rule TrojanDownloader_Win32_Renos_HA{
	meta:
		description = "TrojanDownloader:Win32/Renos.HA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {43 72 69 74 69 63 61 6c 20 53 79 73 74 65 6d 20 57 61 72 6e 69 6e 67 21 20 59 6f 75 72 20 73 79 73 74 65 6d 20 69 73 20 70 72 6f 62 61 62 6c 79 20 69 6e 66 65 63 74 65 64 20 77 69 74 68 20 61 20 76 65 72 73 69 6f 6e 20 6f 66 20 53 70 79 77 61 72 65 2e 49 45 50 61 73 73 2e 74 68 69 65 66 } //01 00  Critical System Warning! Your system is probably infected with a version of Spyware.IEPass.thief
		$a_00_1 = {73 63 61 6e 6e 65 72 2e 72 61 70 69 64 61 6e 74 69 76 69 72 75 73 2e 63 6f 6d } //01 00  scanner.rapidantivirus.com
		$a_01_2 = {69 53 53 44 5f 43 4d 00 } //01 00  卩䑓䍟M
		$a_01_3 = {4d 69 63 72 25 73 6e 74 56 65 72 25 73 } //01 00  Micr%sntVer%s
		$a_00_4 = {41 74 74 6e 21 20 43 72 69 74 69 63 61 6c 20 53 79 73 74 65 6d 20 57 61 72 6e 69 6e 67 } //00 00  Attn! Critical System Warning
	condition:
		any of ($a_*)
 
}