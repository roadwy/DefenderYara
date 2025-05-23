
rule Trojan_Win32_Vundo_CQ_dll{
	meta:
		description = "Trojan:Win32/Vundo.CQ!dll,SIGNATURE_TYPE_PEHSTR,ffffffd2 00 ffffffd2 00 12 00 00 "
		
	strings :
		$a_01_0 = {31 36 42 34 33 35 46 36 2d 42 36 43 45 2d 34 46 32 34 2d 41 35 36 38 2d 39 34 34 42 32 37 45 44 39 31 39 43 } //100 16B435F6-B6CE-4F24-A568-944B27ED919C
		$a_01_1 = {74 61 72 67 65 74 74 65 64 62 61 6e 6e 65 72 2e 62 69 7a } //100 targettedbanner.biz
		$a_01_2 = {26 00 74 00 61 00 69 00 6c 00 3d 00 } //1 &tail=
		$a_01_3 = {26 00 65 00 78 00 63 00 65 00 65 00 64 00 3d 00 } //1 &exceed=
		$a_01_4 = {26 00 74 00 6d 00 3d 00 } //1 &tm=
		$a_01_5 = {26 00 69 00 64 00 3d 00 } //1 &id=
		$a_01_6 = {26 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 3d 00 } //1 &version=
		$a_01_7 = {26 00 63 00 6c 00 69 00 63 00 6b 00 65 00 64 00 3d 00 } //1 &clicked=
		$a_01_8 = {73 00 68 00 6f 00 77 00 65 00 64 00 3d 00 } //1 showed=
		$a_01_9 = {49 00 73 00 52 00 6f 00 74 00 61 00 74 00 6f 00 72 00 50 00 6f 00 70 00 75 00 70 00 } //1 IsRotatorPopup
		$a_01_10 = {63 00 6c 00 69 00 63 00 6b 00 6c 00 69 00 6d 00 69 00 74 00 } //1 clicklimit
		$a_01_11 = {72 00 65 00 66 00 72 00 65 00 73 00 68 00 5f 00 74 00 69 00 6d 00 65 00 } //1 refresh_time
		$a_01_12 = {67 00 6c 00 6f 00 62 00 5f 00 63 00 6c 00 69 00 63 00 6b 00 5f 00 6c 00 69 00 6d 00 69 00 74 00 } //1 glob_click_limit
		$a_01_13 = {6d 00 61 00 78 00 5f 00 69 00 6d 00 70 00 72 00 65 00 73 00 73 00 } //1 max_impress
		$a_01_14 = {50 00 6f 00 70 00 75 00 70 00 4d 00 67 00 72 00 } //1 PopupMgr
		$a_01_15 = {49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 5f 00 53 00 65 00 72 00 76 00 65 00 72 00 } //1 Internet Explorer_Server
		$a_01_16 = {43 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 2d 00 54 00 79 00 70 00 65 00 3a 00 20 00 61 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 2f 00 78 00 2d 00 77 00 77 00 77 00 2d 00 66 00 6f 00 72 00 6d 00 2d 00 75 00 72 00 6c 00 65 00 6e 00 63 00 6f 00 64 00 65 00 64 00 } //1 Content-Type: application/x-www-form-urlencoded
		$a_01_17 = {6f 00 70 00 65 00 72 00 61 00 } //1 opera
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1) >=210
 
}