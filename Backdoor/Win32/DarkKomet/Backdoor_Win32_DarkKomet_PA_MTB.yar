
rule Backdoor_Win32_DarkKomet_PA_MTB{
	meta:
		description = "Backdoor:Win32/DarkKomet.PA!MTB,SIGNATURE_TYPE_PEHSTR,08 00 08 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 53 38 62 30 42 75 34 73 49 75 65 6f 6d 79 49 67 77 76 57 39 2f 38 74 44 46 6d 65 4c 6a 4b 4e 79 32 61 52 48 41 54 52 5a 35 2f 66 6e 48 6b 64 65 46 41 37 79 73 48 41 59 61 55 6d 41 7a 39 2f 6b 59 39 39 5f 56 58 6b 39 71 36 41 4e 4c 4a 52 45 59 6f 32 22 } //01 00  Go build ID: "S8b0Bu4sIueomyIgwvW9/8tDFmeLjKNy2aRHATRZ5/fnHkdeFA7ysHAYaUmAz9/kY99_VXk9q6ANLJREYo2"
		$a_01_1 = {45 6e 63 72 79 70 74 } //01 00  Encrypt
		$a_01_2 = {61 74 20 20 66 70 3d 20 69 73 20 20 6c 72 3a 20 6f 66 20 20 6f 6e 20 20 70 63 3d 20 73 70 3a 20 73 70 3d } //01 00  at  fp= is  lr: of  on  pc= sp: sp=
		$a_01_3 = {6d 3d 2b 49 6e 66 2c 20 6e 20 2d 49 6e 66 2e 62 61 74 2e 63 6d 64 2e 63 6f 6d 2e 65 78 65 } //00 00  m=+Inf, n -Inf.bat.cmd.com.exe
		$a_01_4 = {00 5d 04 00 00 } //fc 33 
	condition:
		any of ($a_*)
 
}