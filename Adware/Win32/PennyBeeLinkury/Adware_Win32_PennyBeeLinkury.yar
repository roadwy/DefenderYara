
rule Adware_Win32_PennyBeeLinkury{
	meta:
		description = "Adware:Win32/PennyBeeLinkury,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4d 6f 6e 65 74 69 7a 61 74 69 6f 6e 2e 49 6e 6a 65 63 74 41 70 70 00 44 6c 6c 49 6e 6a 65 63 74 69 6f 6e 52 65 73 75 6c 74 00 44 6c 6c 49 6e 6a 65 63 74 6f 72 00 } //1 潍敮楴慺楴湯䤮橮捥䅴灰䐀汬湉敪瑣潩剮獥汵t汄䥬橮捥潴r
		$a_03_1 = {5c 4d 6f 6e 65 74 69 7a 61 74 69 6f 6e 5c 53 6d 61 72 74 62 61 72 2e 4d 6f 6e 65 74 69 7a 61 74 69 6f 6e 2e 49 6e 6a 65 63 74 41 70 70 5c 6f 62 6a [0-04] 5c 52 65 6c 65 61 73 65 5c 73 6d 69 61 2e 70 64 62 } //1
		$a_01_2 = {6e 00 74 00 64 00 69 00 73 00 5f 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 } //1 ntdis_32.dll
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Adware_Win32_PennyBeeLinkury_2{
	meta:
		description = "Adware:Win32/PennyBeeLinkury,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 65 6e 6e 79 42 65 65 57 2e 65 78 65 } //10 PennyBeeW.exe
		$a_01_1 = {5f 72 65 66 72 65 73 68 49 6e 6a 65 63 74 69 6f 6e 49 6e 73 74 72 75 63 74 69 6f 6e 73 54 69 6d 65 72 } //1 _refreshInjectionInstructionsTimer
		$a_01_2 = {3c 45 78 74 65 72 6e 61 6c 49 6e 6a 65 63 74 69 6f 6e 73 3e 6b 5f 5f 42 61 63 6b 69 6e 67 46 69 65 6c 64 } //1 <ExternalInjections>k__BackingField
		$a_01_3 = {3c 52 65 64 69 72 65 63 74 69 6f 6e 54 61 72 67 65 74 55 72 6c 3e 6b 5f 5f 42 61 63 6b 69 6e 67 46 69 65 6c 64 } //1 <RedirectionTargetUrl>k__BackingField
		$a_01_4 = {67 65 74 5f 50 72 6f 78 79 50 72 6f 74 65 63 74 6f 72 49 6e 74 65 72 76 61 6c 4d 69 6e 75 74 65 73 } //1 get_ProxyProtectorIntervalMinutes
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=14
 
}
rule Adware_Win32_PennyBeeLinkury_3{
	meta:
		description = "Adware:Win32/PennyBeeLinkury,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 00 74 00 74 00 70 00 73 00 49 00 6e 00 6a 00 65 00 63 00 74 00 69 00 6f 00 6e 00 ?? ?? 48 00 74 00 74 00 70 00 49 00 6e 00 6a 00 65 00 63 00 74 00 69 00 6f 00 6e 00 ?? ?? 42 00 48 00 4f 00 3a 00 20 00 4f 00 6e 00 44 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 43 00 6f 00 6d 00 70 00 6c 00 65 00 74 00 65 00 } //1
		$a_01_1 = {4c 69 6e 6b 75 72 79 49 6e 74 65 72 6e 65 74 45 78 70 6c 6f 72 65 72 42 48 4f } //1 LinkuryInternetExplorerBHO
		$a_03_2 = {4e 00 6f 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 ?? ?? 33 00 31 00 41 00 44 00 34 00 30 00 30 00 44 00 2d 00 31 00 42 00 30 00 36 00 2d 00 34 00 45 00 33 00 33 00 2d 00 41 00 35 00 39 00 41 00 2d 00 39 00 30 00 43 00 32 00 43 00 31 00 34 00 30 00 43 00 42 00 41 00 30 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}