
rule TrojanDownloader_Win32_Discord_ARAQ_MTB{
	meta:
		description = "TrojanDownloader:Win32/Discord.ARAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 04 00 "
		
	strings :
		$a_01_0 = {2f 50 6f 77 65 72 73 68 65 6c 6c 2d 54 6f 6b 65 6e 2d 47 72 61 62 62 65 72 2f } //04 00  /Powershell-Token-Grabber/
		$a_01_1 = {2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 55 6e 72 65 73 74 72 69 63 74 65 64 20 2d 46 6f 72 63 65 } //04 00  -ExecutionPolicy Unrestricted -Force
		$a_01_2 = {62 79 70 61 73 73 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 68 69 64 64 65 6e 20 2d 66 69 6c 65 } //00 00  bypass -WindowStyle hidden -file
	condition:
		any of ($a_*)
 
}