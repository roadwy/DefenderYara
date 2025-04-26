
rule Trojan_Win32_Webnavi_A{
	meta:
		description = "Trojan:Win32/Webnavi.A,SIGNATURE_TYPE_PEHSTR,07 00 07 00 0a 00 00 "
		
	strings :
		$a_01_0 = {3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 6f 6e 63 65 2e 65 78 65 } //1 :\windows\system32\once.exe
		$a_01_1 = {5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 71 71 2e 69 63 6f } //1 \windows\system32\qq.ico
		$a_01_2 = {2f 6f 6e 63 65 2e 68 74 6d 3f } //1 /once.htm?
		$a_01_3 = {5c 5b 4d 41 49 4e 55 52 4c 3a 28 2e 2a 3f 29 5c 5d } //1 \[MAINURL:(.*?)\]
		$a_01_4 = {77 77 77 2e 62 61 69 64 75 2e 63 6f 6d 2f 73 3f 77 6f 72 64 3d 25 73 26 69 65 3d 75 74 66 2d 38 26 74 6e 3d 6c 61 69 79 69 62 61 5f } //1 www.baidu.com/s?word=%s&ie=utf-8&tn=laiyiba_
		$a_01_5 = {77 77 77 2e 68 61 6f 31 32 33 2e 63 6e 2f 3f 69 65 } //1 www.hao123.cn/?ie
		$a_01_6 = {3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 6f 65 6d 6c 69 6e 6b 69 63 6f 6e 2e 69 63 6f } //1 :\windows\system32\oemlinkicon.ico
		$a_01_7 = {48 61 6f 31 32 33 cd f8 d6 b7 b5 bc ba bd 00 } //1
		$a_01_8 = {22 73 75 72 65 68 22 20 22 51 51 2e 65 78 65 22 } //1 "sureh" "QQ.exe"
		$a_01_9 = {68 74 74 70 3a 2f 2f 64 2e 6c 61 69 79 69 62 61 2e 63 6f 6d 2f } //1 http://d.laiyiba.com/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=7
 
}