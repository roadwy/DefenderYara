
rule Worm_Win32_Autorun_ADZ{
	meta:
		description = "Worm:Win32/Autorun.ADZ,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 09 00 0b 00 00 02 00 "
		
	strings :
		$a_01_0 = {75 73 65 72 61 6e 64 70 63 3d 25 73 26 61 64 6d 69 6e 3d 25 73 26 6f 73 3d 25 73 26 68 77 69 64 3d 25 73 26 6f 77 6e 65 72 69 64 3d 25 73 } //01 00  userandpc=%s&admin=%s&os=%s&hwid=%s&ownerid=%s
		$a_01_1 = {5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 67 70 72 65 73 75 6c 74 6c 2e 65 78 65 } //01 00  \Application Data\gpresultl.exe
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 48 53 65 74 74 69 6e 67 5c 00 } //01 00 
		$a_01_3 = {69 64 7c 00 } //01 00  摩|
		$a_01_4 = {44 4c 7c 00 } //01 00  䱄|
		$a_01_5 = {55 50 7c 00 } //01 00  偕|
		$a_01_6 = {56 49 7c 00 } //01 00  䥖|
		$a_01_7 = {55 4e 7c 00 } //01 00  乕|
		$a_01_8 = {7a 65 72 6f 78 63 6f 64 65 2e 6e 65 74 2f 68 65 72 70 6e 65 74 2f } //01 00  zeroxcode.net/herpnet/
		$a_01_9 = {61 75 74 6f 72 75 6e 2e 69 6e 66 00 6a 6b 70 2e 65 78 65 00 } //01 00 
		$a_01_10 = {48 65 72 70 65 73 4d 00 } //00 00  效灲獥M
	condition:
		any of ($a_*)
 
}