
rule TrojanDownloader_Win32_Dembr_A{
	meta:
		description = "TrojanDownloader:Win32/Dembr.A,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0c 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {41 8d 70 01 8d 9b 00 00 00 00 8a 10 40 84 d2 75 f9 2b c6 3b c8 72 d7 5f a1 } //01 00 
		$a_01_1 = {54 47 49 49 54 47 4d 31 47 53 45 52 3a 3c 34 39 31 4d 52 50 58 3a 36 3d 34 35 34 31 35 47 51 34 34 34 36 34 35 36 } //01 00  TGIITGM1GSER:<491MRPX:6=45415GQ4446456
		$a_01_2 = {57 53 4a 58 5b 45 56 49 60 60 51 6d 67 76 73 77 73 6a 78 60 60 5b 6d 72 68 73 7b 77 24 52 58 60 60 47 79 76 76 69 72 78 5a 69 76 77 6d 73 72 } //01 00  WSJX[EVI``Qmgvswsjx``[mrhs{w$RX``GyvvirxZivwmsr
		$a_01_3 = {60 60 78 6d 72 7d 6d 72 6d 35 } //01 00  ``xmr}mrm5
		$a_01_4 = {4d 72 78 69 76 7a 65 70 24 29 68 24 6d 77 24 77 69 78 24 57 79 67 67 69 77 77 25 20 68 73 7b 72 } //00 00  Mrxivzep$)h$mw$wix$Wyggiww% hs{r
		$a_00_5 = {87 } //10 00 
	condition:
		any of ($a_*)
 
}