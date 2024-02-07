
rule TrojanDownloader_BAT_AsyncRAT_BA_MTB{
	meta:
		description = "TrojanDownloader:BAT/AsyncRAT.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {49 00 6a 00 7a 00 77 00 6b 00 75 00 6b 00 75 00 69 00 7a 00 6c 00 65 00 6f 00 6b 00 6b 00 74 00 77 00 68 00 6b 00 63 00 6f 00 77 00 61 00 2e 00 46 00 73 00 76 00 66 00 65 00 75 00 64 00 72 00 69 00 70 00 75 00 } //02 00  Ijzwkukuizleokktwhkcowa.Fsvfeudripu
		$a_01_1 = {43 00 75 00 77 00 6c 00 76 00 76 00 63 00 68 00 71 00 } //02 00  Cuwlvvchq
		$a_01_2 = {65 64 6f 6d 20 53 4f 44 20 6e 69 20 6e 75 72 20 65 62 20 74 6f 6e 6e 61 63 20 6d 61 72 67 6f 72 70 20 73 69 68 54 21 } //01 00  edom SOD ni nur eb tonnac margorp sihT!
		$a_01_3 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //02 00  powershell
		$a_01_4 = {53 00 74 00 61 00 72 00 74 00 2d 00 53 00 6c 00 65 00 65 00 70 00 20 00 2d 00 53 00 65 00 63 00 6f 00 6e 00 64 00 73 00 20 00 39 00 3b 00 53 00 74 00 61 00 72 00 74 00 2d 00 53 00 6c 00 65 00 65 00 70 00 20 00 2d 00 53 00 65 00 63 00 6f 00 6e 00 64 00 73 00 20 00 39 00 3b 00 } //00 00  Start-Sleep -Seconds 9;Start-Sleep -Seconds 9;
	condition:
		any of ($a_*)
 
}