
rule TrojanDownloader_Win32_Adload_DK_bit{
	meta:
		description = "TrojanDownloader:Win32/Adload.DK!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 56 45 52 59 53 49 4c 45 4e 54 } //01 00  /VERYSILENT
		$a_01_1 = {2f 6b 4c 33 43 75 59 44 57 75 46 2f 59 78 35 63 4a 75 72 33 65 58 2f 6a 66 6b 30 30 32 31 2e 65 78 65 } //01 00  /kL3CuYDWuF/Yx5cJur3eX/jfk0021.exe
		$a_01_2 = {44 4f 57 4e 4c 4f 41 44 41 4e 44 45 58 45 43 55 54 45 } //01 00  DOWNLOADANDEXECUTE
		$a_01_3 = {63 6c 61 73 73 3a 54 43 4f 4e 54 52 4f 4c 7c 48 49 44 45 7c } //00 00  class:TCONTROL|HIDE|
	condition:
		any of ($a_*)
 
}