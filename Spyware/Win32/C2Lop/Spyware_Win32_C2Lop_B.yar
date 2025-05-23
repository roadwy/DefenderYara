
rule Spyware_Win32_C2Lop_B{
	meta:
		description = "Spyware:Win32/C2Lop.B,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0d 00 0d 00 00 "
		
	strings :
		$a_00_0 = {03 f0 81 f6 b3 3a 29 f0 e8 } //2
		$a_00_1 = {55 72 6c 4d 6b 53 65 74 53 65 73 73 69 6f 6e 4f 70 74 69 6f 6e } //1 UrlMkSetSessionOption
		$a_01_2 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //1 CreateRemoteThread
		$a_00_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_00_4 = {e0 34 44 00 } //1
		$a_00_5 = {34 35 44 00 } //1 㔴D
		$a_00_6 = {04 35 44 00 } //1 㔄D
		$a_00_7 = {1c 35 44 00 } //1 㔜D
		$a_00_8 = {dc 3e 44 00 } //1
		$a_00_9 = {4c 3a 44 00 } //1 㩌D
		$a_00_10 = {78 19 44 00 } //1
		$a_00_11 = {8c 19 44 00 } //1
		$a_00_12 = {a8 19 44 00 } //1
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1) >=13
 
}
rule Spyware_Win32_C2Lop_B_2{
	meta:
		description = "Spyware:Win32/C2Lop.B,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0e 00 0e 00 00 "
		
	strings :
		$a_00_0 = {03 f0 81 f6 b3 3a 29 f0 e8 } //2
		$a_00_1 = {55 72 6c 4d 6b 53 65 74 53 65 73 73 69 6f 6e 4f 70 74 69 6f 6e } //1 UrlMkSetSessionOption
		$a_01_2 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //1 CreateRemoteThread
		$a_00_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_00_4 = {24 2c 25 44 00 } //1
		$a_00_5 = {8c 68 44 25 44 00 } //1
		$a_00_6 = {a0 68 5c 25 44 00 } //1
		$a_00_7 = {dc 09 44 00 } //1
		$a_00_8 = {f8 20 44 00 } //1
		$a_00_9 = {a4 09 44 00 } //1
		$a_00_10 = {c7 04 24 34 03 44 00 } //1
		$a_00_11 = {89 85 f8 e7 ff ff c7 04 24 a4 09 44 00 } //1
		$a_00_12 = {08 e8 ff ff c7 04 24 c0 09 44 00 } //1
		$a_00_13 = {a0 c7 04 24 04 2f 44 00 } //1
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1+(#a_00_13  & 1)*1) >=14
 
}
rule Spyware_Win32_C2Lop_B_3{
	meta:
		description = "Spyware:Win32/C2Lop.B,SIGNATURE_TYPE_PEHSTR_EXT,08 00 06 00 0b 00 00 "
		
	strings :
		$a_00_0 = {4b 52 53 79 73 74 65 6d 20 76 31 2e 30 } //2 KRSystem v1.0
		$a_00_1 = {41 49 45 4e 20 } //1 AIEN 
		$a_00_2 = {55 72 6c 4d 6b 53 65 74 53 65 73 73 69 6f 6e 4f 70 74 69 6f 6e } //1 UrlMkSetSessionOption
		$a_01_3 = {61 65 72 6f 00 00 00 00 52 4b 4d 57 } //1
		$a_01_4 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //1 CreateRemoteThread
		$a_00_5 = {68 74 74 70 3a 2f 2f 75 70 64 2e 6c 6f 70 2e 63 6f 6d 2f 75 70 64 2f 63 68 65 63 6b } //2 http://upd.lop.com/upd/check
		$a_00_6 = {68 74 74 70 3a 2f 2f 75 70 64 2e 7a 6f 6e 65 2d 6d 65 64 69 61 2e 63 6f 6d 2f 75 70 64 2f 63 68 65 63 6b } //2 http://upd.zone-media.com/upd/check
		$a_00_7 = {c1 e0 10 03 f0 81 f6 b3 3a 29 f0 } //2
		$a_00_8 = {36 34 33 45 43 30 46 42 44 42 32 44 46 35 38 34 42 41 43 39 42 43 43 36 39 35 42 39 38 41 41 33 44 32 45 35 44 44 38 36 32 37 44 38 41 33 44 35 } //2 643EC0FBDB2DF584BAC9BCC695B98AA3D2E5DD8627D8A3D5
		$a_00_9 = {44 6f 77 6e 6c 6f 61 64 20 55 42 41 67 65 6e 74 } //1 Download UBAgent
		$a_00_10 = {75 70 64 62 68 6f 2e 64 6c 6c } //1 updbho.dll
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*2+(#a_00_6  & 1)*2+(#a_00_7  & 1)*2+(#a_00_8  & 1)*2+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1) >=6
 
}
rule Spyware_Win32_C2Lop_B_4{
	meta:
		description = "Spyware:Win32/C2Lop.B,SIGNATURE_TYPE_PEHSTR_EXT,08 00 06 00 0b 00 00 "
		
	strings :
		$a_00_0 = {38 42 30 38 43 39 34 44 33 46 33 34 45 32 44 33 35 34 46 32 39 33 41 46 45 36 37 37 30 37 } //2 8B08C94D3F34E2D354F293AFE67707
		$a_00_1 = {37 33 32 37 36 35 30 34 30 34 46 45 32 30 37 42 46 37 44 39 43 30 39 44 41 34 37 42 33 38 45 30 } //2 7327650404FE207BF7D9C09DA47B38E0
		$a_00_2 = {34 44 33 41 38 44 43 33 46 39 43 34 46 32 39 45 45 30 44 42 } //2 4D3A8DC3F9C4F29EE0DB
		$a_00_3 = {32 39 35 43 37 41 32 31 46 32 39 45 32 44 35 36 42 44 35 39 45 41 38 46 46 39 37 42 } //2 295C7A21F29E2D56BD59EA8FF97B
		$a_00_4 = {36 42 32 33 44 32 38 34 38 43 34 37 31 45 39 31 46 34 32 42 39 45 39 45 } //2 6B23D2848C471E91F42B9E9E
		$a_00_5 = {43 43 33 35 46 39 38 46 43 38 45 46 46 44 43 30 42 33 39 32 } //2 CC35F98FC8EFFDC0B392
		$a_01_6 = {42 61 64 20 45 6c 6d 6f } //1 Bad Elmo
		$a_01_7 = {59 6f 75 20 6d 75 73 74 20 69 6e 73 74 61 6c 6c 20 74 68 69 73 20 73 6f 66 74 77 61 72 65 20 61 73 20 70 61 72 74 20 6f 66 20 74 68 65 20 70 61 72 65 6e 74 20 70 72 6f 67 72 61 6d 2e 20 20 50 72 65 73 73 20 4f 4b 20 74 6f 20 65 78 69 74 2e } //1 You must install this software as part of the parent program.  Press OK to exit.
		$a_01_8 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //1 CreateRemoteThread
		$a_00_9 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_00_10 = {46 6c 75 73 68 49 6e 73 74 72 75 63 74 69 6f 6e 43 61 63 68 65 } //1 FlushInstructionCache
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2+(#a_00_5  & 1)*2+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1) >=6
 
}
rule Spyware_Win32_C2Lop_B_5{
	meta:
		description = "Spyware:Win32/C2Lop.B,SIGNATURE_TYPE_PEHSTR,16 00 16 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 69 6e 74 65 72 6e 65 74 20 65 78 70 6c 6f 72 65 72 5c 74 6f 6f 6c 62 61 72 } //1 software\microsoft\internet explorer\toolbar
		$a_01_1 = {68 74 74 70 3a 2f 2f 25 73 2f 73 65 61 72 63 68 2f 73 65 61 72 63 68 2e 63 67 69 3f 73 72 63 3d 61 75 74 6f 73 65 61 72 63 68 26 73 3d 25 73 } //1 http://%s/search/search.cgi?src=autosearch&s=%s
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 25 73 00 54 72 69 6e 69 74 79 41 59 42 } //10 潓瑦慷敲╜s牔湩瑩䅹䉙
		$a_01_3 = {73 77 69 73 68 74 6f 6f 6c 62 61 6e 64 00 } //10 睳獩瑨潯扬湡d
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10) >=22
 
}
rule Spyware_Win32_C2Lop_B_6{
	meta:
		description = "Spyware:Win32/C2Lop.B,SIGNATURE_TYPE_PEHSTR,0c 00 0a 00 06 00 00 "
		
	strings :
		$a_01_0 = {39 38 30 34 37 42 30 33 35 34 45 36 34 37 32 45 32 31 45 37 45 36 35 38 43 35 38 31 45 41 41 35 } //2 98047B0354E6472E21E7E658C581EAA5
		$a_01_1 = {38 46 35 36 39 43 35 39 42 42 44 34 42 30 35 42 41 46 44 33 39 36 33 41 33 41 30 42 32 32 } //2 8F569C59BBD4B05BAFD3963A3A0B22
		$a_01_2 = {34 44 33 41 38 44 43 33 46 39 43 34 46 32 39 45 45 30 44 42 } //2 4D3A8DC3F9C4F29EE0DB
		$a_01_3 = {36 34 33 45 43 30 46 42 44 42 32 44 46 35 38 34 42 41 43 39 42 43 43 36 39 35 42 39 38 41 41 33 44 32 45 35 44 44 38 36 32 37 44 38 41 33 44 35 } //2 643EC0FBDB2DF584BAC9BCC695B98AA3D2E5DD8627D8A3D5
		$a_01_4 = {44 45 4c 41 46 46 49 44 00 } //2
		$a_01_5 = {37 36 30 42 43 39 35 35 35 43 31 31 36 46 45 42 34 37 32 38 31 30 46 36 46 30 35 44 45 46 39 37 41 46 45 36 36 41 37 34 41 32 45 35 36 42 45 34 32 } //2 760BC9555C116FEB472810F6F05DEF97AFE66A74A2E56BE42
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=10
 
}
rule Spyware_Win32_C2Lop_B_7{
	meta:
		description = "Spyware:Win32/C2Lop.B,SIGNATURE_TYPE_PEHSTR,0a 00 08 00 0c 00 00 "
		
	strings :
		$a_01_0 = {c1 e0 10 03 f0 81 f6 b3 3a 29 f0 } //2
		$a_01_1 = {25 01 00 00 80 79 05 48 83 c8 fe 40 f7 d8 1b c0 83 e0 02 83 c0 ff 03 45 fc 50 } //2
		$a_01_2 = {64 ff 30 64 89 20 6a 0d 59 f3 ab 8b fa 64 8b 48 30 8c da f6 c2 04 75 74 ba 6c 02 fe 7f 8a 22 80 fc 04 8a 42 04 72 05 80 fc 05 76 04 66 b8 33 03 c1 e0 10 66 b8 46 05 ab 8b 51 0c 8b 42 1c 8b 58 08 b8 } //2
		$a_01_3 = {ff d6 ab 3b c3 8d ab 00 00 03 00 72 15 3b c5 73 11 2d f1 00 00 00 6a 5f 59 e8 a6 00 00 00 85 c9 75 66 b8 } //2
		$a_01_4 = {60 8e 46 00 e8 c8 7d fc ff 83 c4 08 8b 95 0c ff ff ff 52 68 98 8d 46 00 e8 b4 7d fc ff 83 c4 08 8b 85 50 ff } //2
		$a_01_5 = {4c 8a 46 00 e8 de 76 fc ff 83 c4 04 89 45 e4 68 64 8a 46 00 e8 ce 76 fc ff 83 c4 04 89 45 e0 68 78 8a 46 } //2
		$a_01_6 = {31 2e 32 2e 31 00 00 00 31 2e 32 2e 31 00 00 00 } //1
		$a_01_7 = {55 72 6c 4d 6b 53 65 74 53 65 73 73 69 6f 6e 4f 70 74 69 6f 6e } //1 UrlMkSetSessionOption
		$a_01_8 = {46 6c 75 73 68 49 6e 73 74 72 75 63 74 69 6f 6e 43 61 63 68 65 } //1 FlushInstructionCache
		$a_01_9 = {6c 69 73 74 3c 54 3e 20 74 6f 6f 20 6c 6f 6e 67 } //1 list<T> too long
		$a_01_10 = {64 65 71 75 65 3c 54 3e 20 74 6f 6f 20 6c 6f 6e 67 } //1 deque<T> too long
		$a_01_11 = {56 43 32 30 58 43 30 30 55 } //1 VC20XC00U
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=8
 
}