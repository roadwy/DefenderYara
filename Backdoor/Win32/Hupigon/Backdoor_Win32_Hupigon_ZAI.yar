
rule Backdoor_Win32_Hupigon_ZAI{
	meta:
		description = "Backdoor:Win32/Hupigon.ZAI,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_03_0 = {68 94 05 00 00 23 ?? 6a 00 6a 04 50 6a ff ff (55 ?? 15 ??|?? ?? ?? 85) c0 a3 } //3
		$a_00_1 = {66 55 43 4b 5f 41 56 50 } //3 fUCK_AVP
		$a_01_2 = {4d 79 4c 69 76 65 } //1 MyLive
		$a_00_3 = {5c 70 62 6b 5c 72 61 73 70 68 6f 6e 65 2e 70 62 6b } //1 \pbk\rasphone.pbk
		$a_00_4 = {5c 70 65 72 66 63 30 30 38 2e 64 61 74 } //1 \perfc008.dat
		$a_00_5 = {5b 25 64 2f 25 64 2f 25 64 20 25 64 3a 25 64 3a 25 64 5d } //1 [%d/%d/%d %d:%d:%d]
		$a_00_6 = {42 49 54 53 53 65 72 76 69 63 65 4d 61 69 6e } //1 BITSServiceMain
	condition:
		((#a_03_0  & 1)*3+(#a_00_1  & 1)*3+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=6
 
}
rule Backdoor_Win32_Hupigon_ZAI_2{
	meta:
		description = "Backdoor:Win32/Hupigon.ZAI,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4d 6d 4d 30 62 56 31 75 4b 6a 68 64 54 54 51 33 5a 58 4d 31 50 44 35 41 6e 77 3d 3d 40 33 51 4c 7a 34 50 45 43 2f 76 4d 43 76 51 50 37 2b 35 38 3d 00 48 41 48 48 48 48 } //1 浍き噢由橋摨呔㍑塚ㅍ䑐䄵睮㴽㍀䱑㑺䕐⽃䵶癃偑⬷㠵=䅈䡈䡈
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 6d 49 43 52 6f 73 4f 46 54 5c 77 49 4e 44 6f 57 73 20 6e 74 5c 63 55 52 72 45 4e 54 76 45 52 73 49 6f 4e 5c 73 56 63 48 6f 73 54 } //1 SOFTWARE\mICRosOFT\wINDoWs nt\cURrENTvERsIoN\sVcHosT
		$a_01_2 = {25 73 3a 5c 44 6f 43 75 6d 45 6e 74 73 20 41 6e 64 20 53 65 74 54 69 6e 47 73 5c 4c 6f 63 61 6c 53 65 52 56 69 63 65 } //1 %s:\DoCumEnts And SetTinGs\LocalSeRVice
		$a_01_3 = {25 73 5c 25 64 5f 49 6e 64 65 78 2e 54 45 4d 50 } //1 %s\%d_Index.TEMP
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}