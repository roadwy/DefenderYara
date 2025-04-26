
rule TrojanDownloader_BAT_Wisntes_A{
	meta:
		description = "TrojanDownloader:BAT/Wisntes.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 00 53 74 61 72 74 00 } //1
		$a_01_1 = {2f 00 74 00 72 00 61 00 63 00 6b 00 65 00 72 00 2f 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 70 00 68 00 70 00 3f 00 75 00 73 00 65 00 72 00 3d 00 } //1 /tracker/script.php?user=
		$a_03_2 = {1f 1d 0f 00 1a 28 ?? 00 00 06 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}