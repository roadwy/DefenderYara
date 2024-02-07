
rule TrojanDownloader_Win32_Drelotent_A{
	meta:
		description = "TrojanDownloader:Win32/Drelotent.A,SIGNATURE_TYPE_PEHSTR,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 75 6e 69 73 64 72 2e 74 6f 70 2f 6d 61 69 6c 2f 69 6e 64 65 78 2e 70 68 70 3f 69 64 3d } //01 00  ://unisdr.top/mail/index.php?id=
		$a_01_1 = {3a 2f 2f 63 6f 72 70 63 6f 6e 6f 72 2d 64 61 69 6c 79 2e 70 77 2f 6d 61 69 6c 2f 69 6e 64 65 78 2e 70 68 70 3f 69 64 3d } //01 00  ://corpconor-daily.pw/mail/index.php?id=
		$a_01_2 = {3a 2f 2f 73 6f 72 72 79 63 6f 72 70 6d 61 69 6c 2e 73 69 74 65 2f 6d 61 69 6c 2f 69 6e 64 65 78 2e 70 68 70 3f 69 64 3d } //00 00  ://sorrycorpmail.site/mail/index.php?id=
	condition:
		any of ($a_*)
 
}