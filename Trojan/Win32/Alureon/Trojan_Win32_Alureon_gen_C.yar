
rule Trojan_Win32_Alureon_gen_C{
	meta:
		description = "Trojan:Win32/Alureon.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_03_0 = {8a d1 80 c2 ?? 30 14 ?? 83 c1 01 3b ?? 72 f1 c3 } //10
		$a_00_1 = {5b 72 75 6e 73 5f 63 6f 75 6e 74 5f } //1 [runs_count_
		$a_00_2 = {5b 75 72 6c 73 5f 74 6f 5f 73 65 72 66 5f } //1 [urls_to_serf_
		$a_00_3 = {5b 72 65 66 73 5f 74 6f 5f 63 68 61 6e 67 65 5f } //1 [refs_to_change_
	condition:
		((#a_03_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=11
 
}
rule Trojan_Win32_Alureon_gen_C_2{
	meta:
		description = "Trojan:Win32/Alureon.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,53 00 52 00 10 00 00 "
		
	strings :
		$a_00_0 = {69 6e 73 74 61 6c 6c 68 6f 6f 6b } //10 installhook
		$a_00_1 = {77 72 69 74 65 66 69 6c 65 } //10 writefile
		$a_00_2 = {70 72 6f 63 65 73 73 33 32 66 69 72 73 74 } //10 process32first
		$a_00_3 = {63 72 65 61 74 65 74 6f 6f 6c 68 65 6c 70 33 32 73 6e 61 70 73 68 6f 74 } //10 createtoolhelp32snapshot
		$a_00_4 = {73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 20 6e 74 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 77 69 6e 6c 6f 67 6f 6e } //10 software\microsoft\windows nt\currentversion\winlogon
		$a_00_5 = {73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 69 6e 74 65 72 6e 65 74 20 65 78 70 6c 6f 72 65 72 5c 74 79 70 65 64 75 72 6c 73 } //10 software\microsoft\internet explorer\typedurls
		$a_01_6 = {2f 6f 63 67 65 74 2e 64 6c 6c } //10 /ocget.dll
		$a_00_7 = {38 35 2e 32 35 35 2e } //5 85.255.
		$a_00_8 = {68 74 74 70 3a 2f 2f 25 73 25 73 26 69 64 3d 25 64 26 71 6e 61 65 73 3d 25 73 } //5 http://%s%s&id=%d&qnaes=%s
		$a_00_9 = {70 6f 72 6e 73 74 61 72 6b 69 6e 67 73 2e 63 6f 6d } //1 pornstarkings.com
		$a_00_10 = {65 78 74 72 65 6d 65 62 75 6c 6c 73 68 69 74 2e 63 6f 6d } //1 extremebullshit.com
		$a_00_11 = {61 64 75 6c 74 77 65 62 6d 61 73 74 65 72 69 6e 66 6f 2e 63 6f 6d } //1 adultwebmasterinfo.com
		$a_00_12 = {61 64 75 6c 74 63 68 61 6d 62 65 72 2e 63 6f 6d } //1 adultchamber.com
		$a_00_13 = {70 6f 72 6e 72 65 73 6f 75 72 63 65 2e 63 6f 6d } //1 pornresource.com
		$a_00_14 = {67 6f 66 75 63 6b 79 6f 75 72 73 65 6c 66 } //1 gofuckyourself
		$a_00_15 = {76 69 64 65 6f 73 63 61 73 68 2e 63 6f 6d } //1 videoscash.com
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*10+(#a_00_5  & 1)*10+(#a_01_6  & 1)*10+(#a_00_7  & 1)*5+(#a_00_8  & 1)*5+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1+(#a_00_13  & 1)*1+(#a_00_14  & 1)*1+(#a_00_15  & 1)*1) >=82
 
}