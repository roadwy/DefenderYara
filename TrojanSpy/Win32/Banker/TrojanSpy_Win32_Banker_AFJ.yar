
rule TrojanSpy_Win32_Banker_AFJ{
	meta:
		description = "TrojanSpy:Win32/Banker.AFJ,SIGNATURE_TYPE_PEHSTR_EXT,40 01 18 01 0d 00 00 "
		
	strings :
		$a_01_0 = {51 37 48 71 53 33 65 6c 42 74 } //100 Q7HqS3elBt
		$a_01_1 = {4b 71 7a 36 4c 35 54 31 4b 61 4c 53 4a 4b 62 33 4b 61 7a 4a 4a 71 50 4b 4e 35 54 39 4a 61 48 46 4c 72 44 53 47 72 4c 49 4b 61 4c 45 4c 35 50 35 4b 62 44 39 4a 71 76 53 4b 62 4c 45 } //100 Kqz6L5T1KaLSJKb3KazJJqPKN5T9JaHFLrDSGrLIKaLEL5P5KbD9JqvSKbLE
		$a_01_2 = {76 70 51 4e 48 62 53 6f 76 72 52 73 6d 6b 4f 73 7a 6a 42 63 39 6f 42 6d } //100 vpQNHbSovrRsmkOszjBc9oBm
		$a_01_3 = {39 66 50 74 4c 66 52 36 58 62 53 63 72 62 42 64 44 66 54 36 4c 70 42 64 4c 6c 52 32 76 5a 52 73 71 6b 4f 64 38 6c } //50 9fPtLfR6XbScrbBdDfT6LpBdLlR2vZRsqkOd8l
		$a_01_4 = {52 4d 76 6a 52 4e 44 6b 42 63 4c 75 50 47 } //20 RMvjRNDkBcLuPG
		$a_01_5 = {49 4b 6a 73 43 72 44 59 48 36 76 38 54 33 61 71 49 61 76 62 53 61 62 45 44 4d 66 4b 49 72 54 70 48 34 6a 77 44 71 62 70 4b 33 39 43 44 5a 4c 42 49 33 48 59 53 35 48 51 44 4a 62 4a 44 35 48 6f } //20 IKjsCrDYH6v8T3aqIavbSabEDMfKIrTpH4jwDqbpK39CDZLBI3HYS5HQDJbJD5Ho
		$a_01_6 = {51 4d 4c 63 53 63 35 6a 50 47 } //20 QMLcSc5jPG
		$a_01_7 = {49 4b 4c 75 53 36 6e 6c 53 63 4b } //20 IKLuS6nlScK
		$a_01_8 = {39 61 4c 6a 4f 4d 62 69 46 47 } //20 9aLjOMbiFG
		$a_01_9 = {39 64 4c 70 50 4e 38 6b 53 36 35 70 53 74 54 6c 53 63 47 7a } //20 9dLpPN8kS65pStTlScGz
		$a_01_10 = {74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 20 6d 70 66 61 6c 65 72 74 2e 65 78 65 20 2f 66 } //20 taskkill /im mpfalert.exe /f
		$a_01_11 = {4c 37 44 68 54 37 39 58 55 47 } //20 L7DhT79XUG
		$a_01_12 = {4d 6f 7a 39 4a 62 44 4b 47 4b 6e 31 48 34 7a 54 } //20 Moz9JbDKGKn1H4zT
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*100+(#a_01_3  & 1)*50+(#a_01_4  & 1)*20+(#a_01_5  & 1)*20+(#a_01_6  & 1)*20+(#a_01_7  & 1)*20+(#a_01_8  & 1)*20+(#a_01_9  & 1)*20+(#a_01_10  & 1)*20+(#a_01_11  & 1)*20+(#a_01_12  & 1)*20) >=280
 
}