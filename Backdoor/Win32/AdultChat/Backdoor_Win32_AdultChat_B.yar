
rule Backdoor_Win32_AdultChat_B{
	meta:
		description = "Backdoor:Win32/AdultChat.B,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0a 00 00 "
		
	strings :
		$a_02_0 = {83 7d 0c 01 75 1f ff 75 18 ff 75 14 ff 75 10 ff 15 90 01 04 8b 4d 20 f7 d8 1b c0 83 e0 03 89 01 33 c0 eb 05 b8 05 40 00 80 90 00 } //4
		$a_00_1 = {25 73 3a 2f 2f 25 73 3a 25 73 40 25 73 3a 25 64 25 73 25 73 } //2 %s://%s:%s@%s:%d%s%s
		$a_00_2 = {5c 25 73 5c 64 69 61 6c 65 72 73 5c 25 73 5c 25 73 2e 65 78 65 } //2 \%s\dialers\%s\%s.exe
		$a_00_3 = {7b 42 35 44 44 39 41 36 34 2d 35 43 34 42 2d 34 61 34 38 2d 42 45 35 36 2d 39 37 43 31 41 38 46 38 35 37 30 38 7d } //2 {B5DD9A64-5C4B-4a48-BE56-97C1A8F85708}
		$a_00_4 = {77 77 77 2e 6b 6a 64 68 65 6e 64 69 65 6c 64 69 6f 75 79 75 2e 63 6f 6d } //2 www.kjdhendieldiouyu.com
		$a_00_5 = {66 61 73 74 76 69 64 65 6f 70 6c 61 79 65 72 6c 69 74 65 43 74 72 6c 20 43 6c 61 73 73 } //2 fastvideoplayerliteCtrl Class
		$a_00_6 = {3a 5a 6f 6e 65 2e 49 64 65 6e 74 69 66 69 65 72 } //1 :Zone.Identifier
		$a_00_7 = {2f 75 73 65 64 6e 73 75 70 64 61 74 65 } //1 /usednsupdate
		$a_00_8 = {2f 70 61 73 73 77 6f 72 64 3a } //1 /password:
		$a_00_9 = {2f 75 73 65 72 6e 61 6d 65 3a 25 73 } //1 /username:%s
	condition:
		((#a_02_0  & 1)*4+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2+(#a_00_5  & 1)*2+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1) >=14
 
}