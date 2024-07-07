
rule TrojanDownloader_Win32_Elsentric_AG_MSR{
	meta:
		description = "TrojanDownloader:Win32/Elsentric.AG!MSR,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 08 00 00 "
		
	strings :
		$a_80_0 = {2f 25 78 2f 6b 65 74 77 65 72 39 30 6f 2f 25 30 32 64 25 30 32 64 25 30 32 64 25 30 32 64 2e 68 74 6d 6c } ///%x/ketwer90o/%02d%02d%02d%02d.html  5
		$a_80_1 = {2f 25 78 2f 61 72 63 68 69 76 65 2f 25 30 32 64 25 30 32 64 25 30 32 64 25 30 32 64 2e 68 74 6d 6c } ///%x/archive/%02d%02d%02d%02d.html  5
		$a_80_2 = {45 6c 69 73 65 31 34 } //Elise14  1
		$a_80_3 = {7b 35 39 34 37 42 41 43 44 2d 36 33 42 46 2d 34 65 37 33 2d 39 35 44 37 2d 30 43 38 41 39 38 41 42 39 35 46 32 7d } //{5947BACD-63BF-4e73-95D7-0C8A98AB95F2}  1
		$a_80_4 = {72 75 6e 65 78 65 20 31 2e 65 78 65 } //runexe 1.exe  1
		$a_80_5 = {72 75 6e 64 6c 6c 20 31 2e 64 6c 6c 2c 44 6c 6c 4d 61 69 6e } //rundll 1.dll,DllMain  1
		$a_80_6 = {70 72 6f 66 69 6c 65 73 2e 69 6e 69 } //profiles.ini  1
		$a_80_7 = {5c 70 72 65 66 73 2e 6a 73 } //\prefs.js  1
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*5+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1) >=11
 
}