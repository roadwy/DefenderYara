
rule TrojanDropper_Win32_Zusy_AH_MTB{
	meta:
		description = "TrojanDropper:Win32/Zusy.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 04 00 00 "
		
	strings :
		$a_01_0 = {69 66 20 65 78 69 73 74 20 61 75 64 69 6f 5c 70 77 72 75 6e 2e 76 62 73 20 63 64 20 61 75 64 69 6f } //10 if exist audio\pwrun.vbs cd audio
		$a_01_1 = {72 65 6e 20 61 70 70 36 34 2e 64 6b 63 20 61 70 70 36 34 2e 62 61 74 } //20 ren app64.dkc app64.bat
		$a_01_2 = {73 74 61 72 74 20 2f 62 20 2f 77 61 69 74 20 61 70 70 36 34 2e 62 61 74 } //30 start /b /wait app64.bat
		$a_01_3 = {69 66 20 65 78 69 73 74 20 41 70 70 36 34 5c 61 64 6d 69 6e 5c 61 70 70 36 34 2e 62 61 74 20 63 64 20 41 70 70 36 34 5c 61 64 6d 69 6e } //40 if exist App64\admin\app64.bat cd App64\admin
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*20+(#a_01_2  & 1)*30+(#a_01_3  & 1)*40) >=100
 
}