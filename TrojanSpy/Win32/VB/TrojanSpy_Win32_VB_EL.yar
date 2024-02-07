
rule TrojanSpy_Win32_VB_EL{
	meta:
		description = "TrojanSpy:Win32/VB.EL,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {48 00 41 00 4b 00 4f 00 50 00 53 00 20 00 4c 00 4f 00 47 00 47 00 45 00 52 00 } //01 00  HAKOPS LOGGER
		$a_01_1 = {6d 00 61 00 6c 00 61 00 72 00 5c 00 } //01 00  malar\
		$a_01_2 = {5c 00 53 00 68 00 6f 00 74 00 5c 00 52 00 65 00 73 00 69 00 6d 00 2e 00 6a 00 70 00 67 00 } //01 00  \Shot\Resim.jpg
		$a_01_3 = {6d 73 6e 73 74 65 61 6c 65 72 } //01 00  msnstealer
		$a_01_4 = {5b 00 50 00 61 00 75 00 73 00 65 00 7c 00 42 00 72 00 65 00 61 00 6b 00 5d 00 } //01 00  [Pause|Break]
		$a_01_5 = {5c 00 47 00 6f 00 6f 00 67 00 6c 00 65 00 55 00 70 00 64 00 61 00 74 00 65 00 2e 00 65 00 78 00 65 00 } //01 00  \GoogleUpdate.exe
		$a_01_6 = {2d 00 5b 00 4b 00 4f 00 50 00 59 00 41 00 4c 00 41 00 4e 00 44 00 49 00 5d 00 2d 00 } //00 00  -[KOPYALANDI]-
		$a_00_7 = {5d 04 00 00 } //76 b6 
	condition:
		any of ($a_*)
 
}