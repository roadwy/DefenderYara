
rule TrojanClicker_Win32_Wbank_A{
	meta:
		description = "TrojanClicker:Win32/Wbank.A,SIGNATURE_TYPE_PEHSTR,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {46 77 2d 62 61 6e 6b 2e 63 6f 2e 6b 72 } //1 Fw-bank.co.kr
		$a_01_1 = {25 73 2f 63 74 72 6c 2f 73 65 61 72 63 68 2e 70 68 70 3f 69 64 3d 25 73 26 77 64 3d 25 73 26 74 62 3d 25 73 26 63 6f 64 65 31 3d 25 73 62 62 31 } //1 %s/ctrl/search.php?id=%s&wd=%s&tb=%s&code1=%sbb1
		$a_01_2 = {25 73 2f 63 74 72 6c 2f 73 65 61 72 63 68 2e 70 68 70 3f 69 64 3d 25 73 26 77 64 3d 25 73 26 74 62 3d 25 73 26 63 6f 64 65 31 3d 25 73 62 62 32 } //1 %s/ctrl/search.php?id=%s&wd=%s&tb=%s&code1=%sbb2
		$a_01_3 = {63 61 73 68 6f 6e 2e 63 6f 2e 6b 72 2f 73 65 61 72 63 68 2f 73 65 61 72 63 68 2e 70 68 70 3f 77 68 65 72 65 3d 74 6f 74 61 6c 26 71 75 65 72 79 3d } //1 cashon.co.kr/search/search.php?where=total&query=
		$a_01_4 = {67 6f 2e 72 65 64 62 75 67 2e 63 6f 2e 6b 72 2f 67 6f 32 2e 68 74 6d 6c 3f 6b 65 79 77 6f 72 64 3d } //1 go.redbug.co.kr/go2.html?keyword=
		$a_01_5 = {67 6f 2e 6e 65 74 70 69 61 2e 63 6f 6d 2f 73 65 61 72 63 68 2e 61 73 70 3f 63 6f 6d 3d 64 72 65 61 6d 77 69 7a 5f 70 6c 75 67 69 6e 26 6b 65 79 77 6f 72 64 3d } //1 go.netpia.com/search.asp?com=dreamwiz_plugin&keyword=
		$a_01_6 = {67 6f 2e 6e 65 74 70 69 61 2e 63 6f 6d 2f 6e 6c 69 61 2e 61 73 70 3f 63 6f 6d 3d 64 72 65 61 6d 77 69 7a 5f 70 6c 75 67 69 6e 26 6b 65 79 77 6f 72 64 3d } //1 go.netpia.com/nlia.asp?com=dreamwiz_plugin&keyword=
		$a_01_7 = {73 65 61 72 63 68 2e 6e 65 74 70 69 61 2e 63 6f 6d 2f 73 65 61 72 63 68 2e 61 73 70 3f 61 63 74 69 6f 6e 3d 73 65 61 72 63 68 26 76 65 72 3d 35 2e 30 26 63 6f 6d 3d 6e 65 74 70 69 61 5f 6e 62 26 6b 65 79 77 6f 72 64 3d } //1 search.netpia.com/search.asp?action=search&ver=5.0&com=netpia_nb&keyword=
		$a_01_8 = {67 6f 2e 6e 65 74 70 69 61 2e 63 6f 6d 2f 6e 6c 69 61 2e 61 73 70 3f 63 6f 6d 3d 6e 65 74 70 69 61 5f 70 6c 75 67 69 6e 26 6b 65 79 77 6f 72 64 3d } //1 go.netpia.com/nlia.asp?com=netpia_plugin&keyword=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}