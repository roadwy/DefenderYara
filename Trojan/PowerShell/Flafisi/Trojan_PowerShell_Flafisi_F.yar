
rule Trojan_PowerShell_Flafisi_F{
	meta:
		description = "Trojan:PowerShell/Flafisi.F,SIGNATURE_TYPE_CMDHSTR_EXT,0b 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_00_0 = {28 00 4e 00 65 00 77 00 2d 00 4f 00 62 00 6a 00 65 00 63 00 74 00 20 00 53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 4e 00 65 00 74 00 2e 00 57 00 65 00 62 00 43 00 6c 00 69 00 65 00 6e 00 74 00 29 00 2e 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 46 00 69 00 6c 00 65 00 28 00 27 00 } //01 00  (New-Object System.Net.WebClient).DownloadFile('
		$a_00_1 = {46 00 6c 00 61 00 73 00 68 00 50 00 6c 00 61 00 79 00 65 00 72 00 2e 00 6a 00 73 00 65 00 27 00 } //01 00  FlashPlayer.jse'
		$a_00_2 = {6d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2d 00 70 00 61 00 74 00 63 00 68 00 2e 00 6a 00 73 00 65 00 27 00 } //00 00  microsoft-patch.jse'
	condition:
		any of ($a_*)
 
}