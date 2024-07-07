
rule Backdoor_BAT_Bladabindi_VPL_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.VPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_81_0 = {4d 42 54 4d 6f 49 6f 47 58 41 67 4b 6b 41 69 79 59 6b 43 54 52 71 48 53 58 6c 48 47 } //1 MBTMoIoGXAgKkAiyYkCTRqHSXlHG
		$a_81_1 = {73 7a 48 53 6e 62 63 42 69 43 51 7a 72 68 48 7a 45 78 4b 76 6b 74 41 71 64 49 64 4c } //1 szHSnbcBiCQzrhHzExKvktAqdIdL
		$a_81_2 = {72 4d 54 79 41 64 62 45 6d 4b 71 48 71 76 6f 45 4d 6a 74 4a 76 6a 4e 4c 4f 6d 7a 62 } //1 rMTyAdbEmKqHqvoEMjtJvjNLOmzb
		$a_81_3 = {71 68 42 4b 44 43 7a 57 6c 72 47 6a 79 4b 52 76 51 73 6d 7a 5a 42 5a 64 54 6e 52 45 } //1 qhBKDCzWlrGjyKRvQsmzZBZdTnRE
		$a_81_4 = {51 73 4f 47 66 47 42 63 4d 46 54 79 79 61 45 66 53 64 78 6b 55 4c 76 5a 6d 58 6c 58 } //1 QsOGfGBcMFTyyaEfSdxkULvZmXlX
		$a_81_5 = {6d 59 58 59 49 4a 52 43 43 64 57 47 74 73 55 41 70 57 53 66 58 73 45 66 56 52 6d 6c } //1 mYXYIJRCCdWGtsUApWSfXsEfVRml
		$a_81_6 = {64 46 4d 6a 6b 75 53 6b 75 43 47 75 46 66 55 69 6c 57 7a 49 61 71 4e 4b 78 74 63 67 41 } //1 dFMjkuSkuCGuFfUilWzIaqNKxtcgA
		$a_81_7 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 ToBase64String
		$a_81_8 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //1 RijndaelManaged
		$a_81_9 = {24 33 31 65 36 33 34 30 63 2d 30 35 32 39 2d 34 63 33 33 2d 38 38 62 63 2d 38 65 37 39 66 64 61 33 31 37 33 33 } //1 $31e6340c-0529-4c33-88bc-8e79fda31733
		$a_01_10 = {77 00 33 00 77 00 70 00 2e 00 65 00 78 00 65 00 } //1 w3wp.exe
		$a_01_11 = {61 00 73 00 70 00 6e 00 65 00 74 00 5f 00 77 00 70 00 2e 00 65 00 78 00 65 00 } //1 aspnet_wp.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=12
 
}