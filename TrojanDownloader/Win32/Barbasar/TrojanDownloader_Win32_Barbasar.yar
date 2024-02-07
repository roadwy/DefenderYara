
rule TrojanDownloader_Win32_Barbasar{
	meta:
		description = "TrojanDownloader:Win32/Barbasar,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 73 33 2d 61 70 2d 6e 6f 72 74 68 65 61 73 74 2d 31 2e 61 6d 61 7a 6f 6e 61 77 73 2e 63 6f 6d 2f 75 70 64 61 74 65 2d 73 65 63 75 72 65 2f 61 73 6d 73 67 72 62 61 72 62 2e 7a 69 70 } //01 00  https://s3-ap-northeast-1.amazonaws.com/update-secure/asmsgrbarb.zip
		$a_01_1 = {53 79 73 74 65 6d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 4b 65 79 62 6f 61 72 64 20 4c 61 79 6f 75 74 73 5c 25 2e 38 78 } //01 00  System\CurrentControlSet\Control\Keyboard Layouts\%.8x
		$a_01_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6d 6f 6c 69 76 2e 63 6f 6d 2e 62 72 2f 73 74 61 74 2f 65 6d 61 69 6c 30 37 30 32 2f } //01 00  http://www.moliv.com.br/stat/email0702/
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 42 6f 72 6c 61 6e 64 5c 44 61 74 61 62 61 73 65 20 45 6e 67 69 6e 65 } //01 00  Software\Borland\Database Engine
		$a_00_4 = {41 00 20 00 74 00 72 00 61 00 6e 00 73 00 61 00 63 00 74 00 69 00 6f 00 6e 00 20 00 69 00 73 00 20 00 61 00 6c 00 72 00 65 00 61 00 64 00 79 00 20 00 61 00 63 00 74 00 69 00 76 00 65 00 } //00 00  A transaction is already active
	condition:
		any of ($a_*)
 
}