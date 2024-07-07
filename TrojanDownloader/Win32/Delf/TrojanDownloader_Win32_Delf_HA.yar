
rule TrojanDownloader_Win32_Delf_HA{
	meta:
		description = "TrojanDownloader:Win32/Delf.HA,SIGNATURE_TYPE_PEHSTR,10 00 10 00 10 00 00 "
		
	strings :
		$a_01_0 = {54 4d 79 53 61 66 65 4c 69 73 74 55 } //1 TMySafeListU
		$a_01_1 = {73 74 72 4c 61 73 74 44 61 74 65 3d } //1 strLastDate=
		$a_01_2 = {2c 4d 54 43 3a } //1 ,MTC:
		$a_01_3 = {31 32 37 2e 30 2e 30 2e 31 } //1 127.0.0.1
		$a_01_4 = {70 65 72 66 73 2e 74 78 74 } //1 perfs.txt
		$a_01_5 = {2d 2d 2d 2d 2d 2d 2d 73 74 61 72 74 20 64 61 74 65 28 } //1 -------start date(
		$a_01_6 = {43 6c 69 65 6e 74 49 50 3a } //1 ClientIP:
		$a_01_7 = {74 6f 74 61 6c 3a } //1 total:
		$a_01_8 = {68 68 3a 6e 6e 3a 73 73 } //1 hh:nn:ss
		$a_01_9 = {4f 73 53 74 61 72 74 44 61 79 73 3a } //1 OsStartDays:
		$a_01_10 = {62 66 6b 71 2e 63 6f 6d } //1 bfkq.com
		$a_01_11 = {65 72 72 6f 72 20 3a 43 72 65 61 74 65 4d 75 74 65 78 } //1 error :CreateMutex
		$a_01_12 = {72 74 6c 36 30 2e 62 70 6c } //1 rtl60.bpl
		$a_01_13 = {40 53 79 73 74 65 6d 40 40 53 74 61 72 74 45 78 65 24 71 71 72 70 32 33 53 79 73 74 65 6d 40 50 61 63 6b 61 67 65 49 6e 66 6f 54 61 62 6c 65 70 31 37 53 79 73 74 65 6d 40 54 4c 69 62 4d 6f 64 75 6c 65 } //1 @System@@StartExe$qqrp23System@PackageInfoTablep17System@TLibModule
		$a_01_14 = {53 65 74 41 70 69 44 65 63 6c 61 72 65 } //1 SetApiDeclare
		$a_01_15 = {53 65 74 53 65 63 75 72 69 74 79 49 6e 66 6f } //1 SetSecurityInfo
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1) >=16
 
}
rule TrojanDownloader_Win32_Delf_HA_2{
	meta:
		description = "TrojanDownloader:Win32/Delf.HA,SIGNATURE_TYPE_PEHSTR,10 00 10 00 10 00 00 "
		
	strings :
		$a_01_0 = {70 65 72 66 6d 6f 6e 73 73 5f 72 74 6c 2e 62 69 6e } //1 perfmonss_rtl.bin
		$a_01_1 = {70 65 72 66 6d 6f 6e 73 73 2e 62 69 6e } //1 perfmonss.bin
		$a_01_2 = {70 65 72 66 73 2e 65 78 65 } //1 perfs.exe
		$a_01_3 = {66 4f 73 53 74 61 72 74 44 61 79 73 3d } //1 fOsStartDays=
		$a_01_4 = {2f 69 6e 73 74 61 6c 6c 20 2f 73 69 6c 65 6e 74 } //1 /install /silent
		$a_01_5 = {73 74 61 72 74 20 70 65 72 66 6d 6f 6e 73 } //1 start perfmons
		$a_01_6 = {55 70 64 61 74 65 4f 6c 64 53 65 72 76 69 63 65 54 6f 4e 65 77 53 65 72 76 69 63 65 3a } //1 UpdateOldServiceToNewService:
		$a_01_7 = {73 6c 65 65 70 28 6e 52 61 6e 64 6f 6d 53 6c 65 65 70 29 3a 6f 6b 3a 6e 6f 77 74 69 6d 65 3d } //1 sleep(nRandomSleep):ok:nowtime=
		$a_01_8 = {31 32 37 2e 30 2e 30 2e 31 } //1 127.0.0.1
		$a_01_9 = {70 65 72 66 73 2e 74 78 74 } //1 perfs.txt
		$a_01_10 = {64 6f 77 6e 65 72 2e 65 78 65 2e 74 78 74 } //1 downer.exe.txt
		$a_01_11 = {70 65 72 66 6d 6f 6e 73 73 2e 65 78 65 2e 74 78 74 } //1 perfmonss.exe.txt
		$a_01_12 = {72 6f 75 74 69 6e 67 2e 74 78 74 } //1 routing.txt
		$a_01_13 = {72 74 6c 36 30 2e 62 70 6c } //1 rtl60.bpl
		$a_01_14 = {40 43 6c 61 73 73 65 73 40 54 54 68 72 65 61 64 40 54 65 72 6d 69 6e 61 74 65 24 71 71 72 76 } //1 @Classes@TThread@Terminate$qqrv
		$a_01_15 = {53 65 74 45 6e 74 72 69 65 73 49 6e 41 63 6c 41 } //1 SetEntriesInAclA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1) >=16
 
}