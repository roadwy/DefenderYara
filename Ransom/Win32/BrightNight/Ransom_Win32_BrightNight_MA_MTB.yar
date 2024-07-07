
rule Ransom_Win32_BrightNight_MA_MTB{
	meta:
		description = "Ransom:Win32/BrightNight.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_01_0 = {72 64 70 72 65 63 6f 76 65 72 79 40 73 6b 69 66 66 2e 63 6f 6d } //5 rdprecovery@skiff.com
		$a_01_1 = {42 72 69 67 68 74 4e 69 67 68 74 } //3 BrightNight
		$a_01_2 = {59 3a 5c 58 3a 5c 57 3a 5c 56 3a 5c 55 3a 5c 54 3a 5c 53 3a 5c 52 3a 5c 51 3a 5c 50 3a 5c 4f 3a 5c 4e 3a 5c 4d 3a 5c 4c 3a 5c 4b 3a 5c 4a 3a 5c 49 3a 5c 48 3a 5c 47 3a 5c 46 3a 5c 45 3a 5c 44 3a 5c 43 3a 5c 42 3a 5c 41 3a 5c 5a 3a 5c } //3 Y:\X:\W:\V:\U:\T:\S:\R:\Q:\P:\O:\N:\M:\L:\K:\J:\I:\H:\G:\F:\E:\D:\C:\B:\A:\Z:\
		$a_01_3 = {5c 52 45 41 44 4d 45 2e 74 78 74 } //3 \README.txt
		$a_01_4 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 4d 00 53 00 41 00 63 00 70 00 69 00 5f 00 54 00 68 00 65 00 72 00 6d 00 61 00 6c 00 5a 00 6f 00 6e 00 65 00 54 00 65 00 6d 00 70 00 65 00 72 00 61 00 74 00 75 00 72 00 65 00 } //3 SELECT * FROM MSAcpi_ThermalZoneTemperature
		$a_01_5 = {4c 6f 63 61 6c 5c 52 75 73 74 42 61 63 6b 74 72 61 63 65 4d 75 74 65 78 } //1 Local\RustBacktraceMutex
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*1) >=18
 
}