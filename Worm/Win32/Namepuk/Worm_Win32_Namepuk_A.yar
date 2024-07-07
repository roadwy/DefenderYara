
rule Worm_Win32_Namepuk_A{
	meta:
		description = "Worm:Win32/Namepuk.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 08 00 00 "
		
	strings :
		$a_01_0 = {46 69 6c 65 43 6f 70 79 20 22 5b 50 75 62 44 69 72 5d 5b 70 75 62 6e 61 6d 65 68 6b 5d 2e 65 78 65 22 20 22 5b 64 72 76 6c 74 72 5d 5b 70 75 62 6e 61 6d 65 68 6b 5d 2e 65 78 65 22 } //1 FileCopy "[PubDir][pubnamehk].exe" "[drvltr][pubnamehk].exe"
		$a_01_1 = {5b 55 73 65 72 4e 61 6d 65 5d 2d 5b 59 65 61 72 5d 5b 4d 6f 6e 74 68 4e 75 6d 5d 5b 44 61 79 4e 75 6d 5d 5b 48 6f 75 72 5d 5b 4d 69 6e 75 74 65 5d 5b 53 65 63 6f 6e 64 5d 2e 6a 70 67 } //1 [UserName]-[Year][MonthNum][DayNum][Hour][Minute][Second].jpg
		$a_01_2 = {46 69 6c 65 45 78 69 73 74 73 20 22 43 3a 5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c 41 6c 6c 20 55 73 65 72 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c 5b 70 75 62 6e 61 6d 65 68 6b 5d 2e 65 78 65 22 20 22 5b 73 74 61 72 74 75 70 63 68 65 63 6b 5d 22 } //1 FileExists "C:\Documents and Settings\All Users\Start Menu\Programs\Startup\[pubnamehk].exe" "[startupcheck]"
		$a_01_3 = {53 65 74 56 61 72 20 22 5b 64 72 76 6c 74 72 5d 22 20 22 5a 3a 5c 22 } //1 SetVar "[drvltr]" "Z:\"
		$a_01_4 = {46 69 6c 65 57 72 69 74 65 20 22 5b 64 72 76 6c 74 72 5d 61 75 74 6f 72 75 6e 2e 69 6e 66 22 20 22 38 22 20 22 73 68 65 6c 6c 5c 6f 70 65 6e 69 6e 5c 63 6f 6d 6d 61 6e 64 3d 5b 70 75 62 6e 61 6d 65 68 6b 5d 2e 65 78 65 22 } //1 FileWrite "[drvltr]autorun.inf" "8" "shell\openin\command=[pubnamehk].exe"
		$a_01_5 = {46 69 6c 65 43 6f 70 79 20 22 5b 50 75 62 44 69 72 5d 5b 70 75 62 6e 61 6d 65 68 6b 5d 2e 65 78 65 22 20 22 5b 64 72 76 6c 74 72 5d 5b 67 65 6e 64 69 72 6c 69 73 74 69 74 65 6d 5d 5c 5b 67 65 6e 64 69 72 6c 69 73 74 69 74 65 6d 5d 2e 65 78 65 22 } //1 FileCopy "[PubDir][pubnamehk].exe" "[drvltr][gendirlistitem]\[gendirlistitem].exe"
		$a_01_6 = {46 69 6c 65 45 78 69 73 74 73 20 22 5b 64 69 72 70 61 74 68 5d 5c 5b 64 69 72 70 61 74 68 67 65 6e 64 69 72 6c 69 73 74 69 74 65 6d 5d 5c 5b 64 69 72 70 61 74 68 67 65 6e 64 69 72 6c 69 73 74 69 74 65 6d 5d 2e 65 78 65 22 20 22 5b 64 69 72 70 61 74 68 67 65 6e 64 69 72 6c 69 73 74 69 74 65 6d 78 5d 22 } //1 FileExists "[dirpath]\[dirpathgendirlistitem]\[dirpathgendirlistitem].exe" "[dirpathgendirlistitemx]"
		$a_01_7 = {47 6f 53 75 62 20 22 64 72 76 73 63 6e 22 } //1 GoSub "drvscn"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=4
 
}