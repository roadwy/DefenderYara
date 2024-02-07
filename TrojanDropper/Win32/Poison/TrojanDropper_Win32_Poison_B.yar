
rule TrojanDropper_Win32_Poison_B{
	meta:
		description = "TrojanDropper:Win32/Poison.B,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 07 00 00 02 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //02 00  SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //02 00  URLDownloadToFileA
		$a_01_2 = {26 26 75 73 65 72 4e 61 6d 65 3d } //02 00  &&userName=
		$a_01_3 = {46 00 4c 00 41 00 53 00 48 00 } //01 00  FLASH
		$a_01_4 = {68 74 74 70 3a 2f 2f 78 69 61 6f 69 62 6f 78 69 70 2e 61 70 70 73 70 6f 74 2e 63 6f 6d 2f } //01 00  http://xiaoiboxip.appspot.com/
		$a_01_5 = {66 75 63 6b 3f 68 6f 73 74 6e 61 6d 65 3d } //01 00  fuck?hostname=
		$a_01_6 = {26 26 73 79 73 74 65 6d 63 70 6f 79 3d } //00 00  &&systemcpoy=
	condition:
		any of ($a_*)
 
}