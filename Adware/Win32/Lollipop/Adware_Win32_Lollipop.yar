
rule Adware_Win32_Lollipop{
	meta:
		description = "Adware:Win32/Lollipop,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_41_0 = {05 33 db 33 d2 c7 41 18 07 00 00 00 89 59 14 68 01 } //1
		$a_6a_1 = {33 d2 33 c0 89 79 18 89 71 14 68 01 00 16 43 c7 41 18 07 00 00 00 90 09 04 00 6a 05 33 90 04 01 02 d2 c0 90 00 00 00 78 53 00 00 0c 00 0c 00 05 00 00 0a 00 10 03 40 33 db 3b c2 0f 9c c3 f6 c3 90 } //3328
		$a_90_2 = {01 00 08 01 3f 41 56 44 6f 67 40 40 01 00 0b 01 3f 41 56 4d 61 6d 6d 61 6c 40 40 01 00 0b 01 3f 41 56 41 6e 69 6d 61 6c 40 40 01 00 08 01 3f 41 56 43 61 74 40 40 00 00 78 53 00 00 0c 00 0c 00 05 00 00 0a 00 10 03 41 33 db 3b ca 0f 9c c3 f6 c3 90 01 01 75 90 00 01 00 08 01 3f 41 56 44 6f 67 40 40 01 00 0b 01 3f 41 56 4d 61 6d 6d 61 6c 40 40 01 00 0b } //257
	condition:
		((#a_41_0  & 1)*1+(#a_6a_1  & 1)*3328+(#a_90_2  & 1)*257) >=2
 
}
rule Adware_Win32_Lollipop_2{
	meta:
		description = "Adware:Win32/Lollipop,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 "
		
	strings :
		$a_03_0 = {40 33 db 3b c2 0f 9c c3 f6 c3 ?? 75 } //10
		$a_01_1 = {3f 41 56 44 6f 67 40 40 } //1 ?AVDog@@
		$a_01_2 = {3f 41 56 4d 61 6d 6d 61 6c 40 40 } //1 ?AVMammal@@
		$a_01_3 = {3f 41 56 41 6e 69 6d 61 6c 40 40 } //1 ?AVAnimal@@
		$a_01_4 = {3f 41 56 43 61 74 40 40 } //1 ?AVCat@@
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=12
 
}
rule Adware_Win32_Lollipop_3{
	meta:
		description = "Adware:Win32/Lollipop,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 "
		
	strings :
		$a_03_0 = {41 33 db 3b ca 0f 9c c3 f6 c3 ?? 75 } //10
		$a_01_1 = {3f 41 56 44 6f 67 40 40 } //1 ?AVDog@@
		$a_01_2 = {3f 41 56 4d 61 6d 6d 61 6c 40 40 } //1 ?AVMammal@@
		$a_01_3 = {3f 41 56 41 6e 69 6d 61 6c 40 40 } //1 ?AVAnimal@@
		$a_01_4 = {3f 41 56 43 61 74 40 40 } //1 ?AVCat@@
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=12
 
}
rule Adware_Win32_Lollipop_4{
	meta:
		description = "Adware:Win32/Lollipop,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 "
		
	strings :
		$a_03_0 = {46 33 db 3b f2 0f 9c c3 f6 c3 ?? 75 } //10
		$a_01_1 = {3f 41 56 44 6f 67 40 40 } //1 ?AVDog@@
		$a_01_2 = {3f 41 56 4d 61 6d 6d 61 6c 40 40 } //1 ?AVMammal@@
		$a_01_3 = {3f 41 56 41 6e 69 6d 61 6c 40 40 } //1 ?AVAnimal@@
		$a_01_4 = {3f 41 56 43 61 74 40 40 } //1 ?AVCat@@
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=12
 
}
rule Adware_Win32_Lollipop_5{
	meta:
		description = "Adware:Win32/Lollipop,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {c7 41 18 07 00 00 00 89 ?? 14 68 90 09 06 00 6a 05 33 ?? 33 } //1
		$a_43_1 = {41 18 07 00 00 00 90 09 04 00 6a 05 33 90 04 01 02 d2 c0 90 00 01 } //1
		$a_c7_2 = {18 } //3840
	condition:
		((#a_03_0  & 1)*1+(#a_43_1  & 1)*1+(#a_c7_2  & 1)*3840) >=3
 
}
rule Adware_Win32_Lollipop_6{
	meta:
		description = "Adware:Win32/Lollipop,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 "
		
	strings :
		$a_03_0 = {03 c6 33 db 3b c2 0f 9c c3 f6 c3 ?? 75 } //10
		$a_01_1 = {3f 41 56 44 6f 67 40 40 } //1 ?AVDog@@
		$a_01_2 = {3f 41 56 4d 61 6d 6d 61 6c 40 40 } //1 ?AVMammal@@
		$a_01_3 = {3f 41 56 41 6e 69 6d 61 6c 40 40 } //1 ?AVAnimal@@
		$a_01_4 = {3f 41 56 43 61 74 40 40 } //1 ?AVCat@@
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=12
 
}
rule Adware_Win32_Lollipop_7{
	meta:
		description = "Adware:Win32/Lollipop,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 "
		
	strings :
		$a_03_0 = {03 c7 33 d2 3b c1 0f 9c c2 f6 c2 ?? 75 } //10
		$a_01_1 = {3f 41 56 44 6f 67 40 40 } //1 ?AVDog@@
		$a_01_2 = {3f 41 56 4d 61 6d 6d 61 6c 40 40 } //1 ?AVMammal@@
		$a_01_3 = {3f 41 56 41 6e 69 6d 61 6c 40 40 } //1 ?AVAnimal@@
		$a_01_4 = {3f 41 56 43 61 74 40 40 } //1 ?AVCat@@
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=12
 
}
rule Adware_Win32_Lollipop_8{
	meta:
		description = "Adware:Win32/Lollipop,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {46 72 65 65 53 65 78 50 6c 61 79 65 72 41 70 70 40 40 } //1 FreeSexPlayerApp@@
		$a_01_1 = {3c 66 73 70 5f 70 61 72 61 6d 73 3e 00 } //1
		$a_01_2 = {4c 00 6f 00 6c 00 6c 00 69 00 70 00 6f 00 70 00 5f 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 72 00 2e 00 65 00 78 00 65 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Adware_Win32_Lollipop_9{
	meta:
		description = "Adware:Win32/Lollipop,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 3f 41 56 4c 6f 6c 6c 69 70 6f 70 46 75 6e 63 40 40 } //2 .?AVLollipopFunc@@
		$a_01_1 = {2e 3f 41 56 42 61 73 65 4c 50 40 40 } //2 .?AVBaseLP@@
		$a_01_2 = {6f 00 6e 00 41 00 63 00 63 00 65 00 73 00 73 00 53 00 63 00 61 00 6e 00 6e 00 69 00 6e 00 67 00 45 00 6e 00 61 00 62 00 6c 00 65 00 64 00 } //1 onAccessScanningEnabled
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}
rule Adware_Win32_Lollipop_10{
	meta:
		description = "Adware:Win32/Lollipop,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 3f 41 56 42 61 73 65 4c 50 40 40 } //3 .?AVBaseLP@@
		$a_01_1 = {49 4e 53 54 41 4c 4c 3a 7c 31 34 36 39 33 7c 7c 38 36 34 30 30 7c 31 7c 30 30 30 37 7c 7c } //4 INSTALL:|14693||86400|1|0007||
		$a_01_2 = {2e 3f 41 56 4c 6f 6c 6c 69 70 6f 70 46 75 6e 63 40 40 } //6 .?AVLollipopFunc@@
		$a_01_3 = {4c 6f 6c 6c 69 70 6f 70 2e 65 78 65 } //5 Lollipop.exe
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*4+(#a_01_2  & 1)*6+(#a_01_3  & 1)*5) >=18
 
}
rule Adware_Win32_Lollipop_11{
	meta:
		description = "Adware:Win32/Lollipop,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_43_0 = {00 6a 05 68 90 01 02 40 00 ff 15 90 01 02 40 00 68 90 01 02 40 00 ff 15 90 01 02 40 00 68 90 01 02 40 00 ff 15 90 01 02 40 00 90 01 01 90 02 01 68 90 01 02 40 00 90 01 01 90 02 01 ff 15 90 01 02 40 00 68 90 01 02 40 00 ff 15 90 01 02 40 00 68 90 01 02 40 00 68 90 01 02 40 00 ff 15 90 01 02 40 00 90 00 00 } //2
	condition:
		((#a_43_0  & 1)*2) >=2
 
}
rule Adware_Win32_Lollipop_12{
	meta:
		description = "Adware:Win32/Lollipop,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 09 00 00 "
		
	strings :
		$a_01_0 = {83 f9 30 74 23 8b 55 08 0f be 42 01 83 f8 3a 74 17 8b 4d 08 0f be 11 83 fa 33 } //10
		$a_01_1 = {3f 41 56 44 6f 67 40 40 } //1 ?AVDog@@
		$a_01_2 = {3f 41 56 4d 61 6d 6d 61 6c 40 40 } //1 ?AVMammal@@
		$a_01_3 = {3f 41 56 41 6e 69 6d 61 6c 40 40 } //1 ?AVAnimal@@
		$a_01_4 = {3f 41 56 43 61 74 40 40 } //1 ?AVCat@@
		$a_01_5 = {66 8b 06 88 07 83 c6 02 47 49 75 f4 9d 61 } //2
		$a_01_6 = {81 c2 28 e5 01 00 89 } //2
		$a_01_7 = {81 c1 28 e5 01 00 89 } //2
		$a_01_8 = {05 28 e5 01 00 89 } //2
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2) >=12
 
}
rule Adware_Win32_Lollipop_13{
	meta:
		description = "Adware:Win32/Lollipop,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {38 37 34 39 34 61 30 62 61 38 66 38 66 39 34 65 66 64 37 64 65 62 63 61 66 39 31 38 } //1 87494a0ba8f8f94efd7debcaf918
		$a_01_1 = {50 75 62 6c 69 73 68 65 72 20 49 44 20 69 73 20 5c 6e 65 65 64 65 64 2e 00 } //1
		$a_01_2 = {50 75 62 6c 69 73 68 65 72 20 49 44 20 69 73 20 69 6e 76 61 6c 69 64 2e 00 } //1
		$a_01_3 = {00 2d 73 75 62 69 64 00 } //1 ⴀ畳楢d
		$a_01_4 = {00 2d 72 6e 61 6d 65 00 } //1 ⴀ湲浡e
		$a_01_5 = {00 2d 6e 6f 6a 73 00 } //1
		$a_03_6 = {68 e8 03 00 00 ff 15 ?? ?? ?? ?? ff 74 24 0c ff 74 24 08 e8 cf ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*1) >=7
 
}
rule Adware_Win32_Lollipop_14{
	meta:
		description = "Adware:Win32/Lollipop,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_02_0 = {53 31 33 5f 00 [0-0f] 00 73 ?? 6f ?? 66 ?? 74 ?? 77 ?? 61 ?? 72 ?? 65 ?? 5c ?? 6c ?? 6f ?? 6c ?? 6c ?? 69 ?? 70 ?? 6f ?? 70 } //5
		$a_01_1 = {6e 75 6d 73 3d 00 00 00 26 61 76 73 3d 31 00 00 26 61 76 73 3d 32 00 00 46 31 5f 00 53 31 5f 00 } //3
		$a_01_2 = {00 46 31 33 5f 00 } //1 䘀㌱_
		$a_01_3 = {00 46 31 32 5f 00 } //1 䘀㈱_
		$a_01_4 = {00 53 31 33 5f 00 } //1 匀㌱_
		$a_01_5 = {00 53 31 32 5f 00 } //1 匀㈱_
	condition:
		((#a_02_0  & 1)*5+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=8
 
}
rule Adware_Win32_Lollipop_15{
	meta:
		description = "Adware:Win32/Lollipop,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 75 62 6c 69 73 68 65 72 20 49 44 20 69 73 20 5c 6e 65 65 64 65 64 2e 00 } //1
		$a_01_1 = {50 75 62 6c 69 73 68 65 72 20 49 44 20 69 73 20 69 6e 76 61 6c 69 64 2e 00 } //1
		$a_03_2 = {50 75 62 6c 69 73 68 65 72 20 49 44 20 69 73 90 0a ff 00 73 ?? 6f ?? 66 ?? 74 ?? 77 ?? 61 ?? 72 ?? 65 ?? 5c ?? 6c ?? 6f ?? 6c ?? 6c ?? 69 ?? 70 ?? 6f ?? 70 } //2
		$a_01_3 = {6e 75 6d 73 3d 00 00 00 26 61 76 73 3d 31 00 00 26 61 76 73 3d 32 00 00 46 31 5f 00 53 31 5f 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*2+(#a_01_3  & 1)*2) >=6
 
}
rule Adware_Win32_Lollipop_16{
	meta:
		description = "Adware:Win32/Lollipop,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 07 00 00 "
		
	strings :
		$a_03_0 = {ff d6 89 5d f0 80 7d ?? 4f 75 06 80 7d ?? 4b 74 1c } //2
		$a_01_1 = {c6 45 80 53 c6 45 81 74 c6 45 82 61 c6 45 83 72 c6 45 84 74 c6 45 85 4d c6 45 86 43 c6 45 87 00 } //2
		$a_01_2 = {c6 85 40 f7 ff ff 49 c6 85 41 f7 ff ff 4e c6 85 42 f7 ff ff 53 c6 85 43 f7 ff ff 54 c6 85 44 f7 ff ff 41 c6 85 45 f7 ff ff 4c c6 85 46 f7 ff ff 4c c6 85 47 f7 ff ff 3a } //2
		$a_01_3 = {4d 43 76 32 44 4c 4c 2e 64 6c 6c 00 53 74 61 72 74 4d 43 00 } //2 䍍㉶䱄⹌汤l瑓牡䵴C
		$a_01_4 = {3c 5f 45 47 4d 43 5f 3e 00 } //2
		$a_01_5 = {26 67 72 70 69 64 3d 00 } //1 朦灲摩=
		$a_01_6 = {53 6f 66 74 77 61 72 65 5c 66 63 6e 5c 78 30 30 } //1 Software\fcn\x00
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=3
 
}
rule Adware_Win32_Lollipop_17{
	meta:
		description = "Adware:Win32/Lollipop,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 0b 00 00 "
		
	strings :
		$a_01_0 = {49 4e 53 54 41 4c 4c 3a 7c 31 34 36 39 33 7c 7c 38 36 34 30 30 7c 31 7c 30 30 30 37 7c 7c } //9 INSTALL:|14693||86400|1|0007||
		$a_01_1 = {4c 6f 6c 6c 69 70 6f 70 2e 65 78 65 } //9 Lollipop.exe
		$a_01_2 = {3f 41 56 44 6f 67 40 40 } //1 ?AVDog@@
		$a_01_3 = {3f 41 56 4d 61 6d 6d 61 6c 40 40 } //1 ?AVMammal@@
		$a_01_4 = {3f 41 56 41 6e 69 6d 61 6c 40 40 } //1 ?AVAnimal@@
		$a_01_5 = {3f 41 56 43 61 74 40 40 } //1 ?AVCat@@
		$a_01_6 = {3f 41 56 4c 6f 6c 6c 69 70 6f 70 46 75 6e 63 40 40 } //1 ?AVLollipopFunc@@
		$a_01_7 = {3f 41 56 6f 62 66 63 6c 73 33 40 40 } //1 ?AVobfcls3@@
		$a_01_8 = {3f 41 56 6f 62 66 63 6c 73 35 40 40 } //1 ?AVobfcls5@@
		$a_01_9 = {3f 41 56 6f 62 66 63 6c 73 38 40 40 } //1 ?AVobfcls8@@
		$a_01_10 = {54 68 65 20 76 61 6c 75 65 20 6f 66 20 45 53 50 20 77 61 73 20 6e 6f 74 20 70 72 6f 70 65 72 6c 79 } //-10 The value of ESP was not properly
	condition:
		((#a_01_0  & 1)*9+(#a_01_1  & 1)*9+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*-10) >=21
 
}
rule Adware_Win32_Lollipop_18{
	meta:
		description = "Adware:Win32/Lollipop,SIGNATURE_TYPE_PEHSTR_EXT,6f 00 6f 00 07 00 00 "
		
	strings :
		$a_01_0 = {38 37 34 39 34 61 30 62 61 38 66 38 66 39 34 65 66 64 37 64 65 62 63 61 66 39 31 38 } //100 87494a0ba8f8f94efd7debcaf918
		$a_01_1 = {73 76 6f 76 66 76 74 76 77 76 61 76 72 76 65 76 5c 76 6c 76 6f 76 6c 76 6c 76 69 76 70 76 6f 76 70 76 } //10 svovfvtvwvavrvev\vlvovlvlvivpvovpv
		$a_01_2 = {4c 76 6f 76 6c 76 6c 76 69 76 70 76 6f 76 70 76 49 76 6e 76 73 76 74 76 61 76 6c 76 6c 76 65 76 72 76 } //10 LvovlvlvivpvovpvIvnvsvtvavlvlvevrv
		$a_01_3 = {73 66 6f 66 66 66 74 66 77 66 61 66 72 66 65 66 5c 66 6c 66 6f 66 6c 66 6c 66 69 66 70 66 6f 66 70 66 } //10 sfoffftfwfafrfef\flfoflflfifpfofpf
		$a_01_4 = {4c 66 6f 66 6c 66 6c 66 69 66 70 66 6f 66 70 66 49 66 6e 66 73 66 74 66 61 66 6c 66 6c 66 65 66 72 66 } //10 LfoflflfifpfofpfIfnfsftfaflflfefrf
		$a_01_5 = {50 75 62 6c 69 73 68 65 72 20 49 44 20 69 73 20 5c 6e 65 65 64 65 64 2e 00 } //1
		$a_01_6 = {50 75 62 6c 69 73 68 65 72 20 49 44 20 69 73 20 69 6e 76 61 6c 69 64 2e 00 } //1
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=111
 
}
rule Adware_Win32_Lollipop_19{
	meta:
		description = "Adware:Win32/Lollipop,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 16 00 00 "
		
	strings :
		$a_01_0 = {38 37 34 39 34 61 30 62 61 38 66 38 66 39 34 65 66 64 37 64 65 62 63 61 66 39 31 38 } //1 87494a0ba8f8f94efd7debcaf918
		$a_03_1 = {46 31 5f 00 53 31 5f 00 38 [0-05] 37 [0-05] 34 [0-05] 39 [0-05] 34 [0-05] 61 } //1
		$a_00_2 = {73 76 6f 76 66 76 74 76 77 76 61 76 72 76 65 76 5c 76 6c 76 6f 76 6c 76 6c 76 69 76 70 76 6f 76 70 76 } //1 svovfvtvwvavrvev\vlvovlvlvivpvovpv
		$a_00_3 = {4c 76 6f 76 6c 76 6c 76 69 76 70 76 6f 76 70 76 49 76 6e 76 73 76 74 76 61 76 6c 76 6c 76 65 76 72 76 } //1 LvovlvlvivpvovpvIvnvsvtvavlvlvevrv
		$a_00_4 = {73 66 6f 66 66 66 74 66 77 66 61 66 72 66 65 66 5c 66 6c 66 6f 66 6c 66 6c 66 69 66 70 66 6f 66 70 66 } //1 sfoffftfwfafrfef\flfoflflfifpfofpf
		$a_00_5 = {53 76 6f 76 66 76 74 76 77 76 61 76 72 76 65 76 5c 76 66 76 63 76 6e 76 } //1 Svovfvtvwvavrvev\vfvcvnv
		$a_00_6 = {73 4f 6f 44 66 66 74 71 77 71 61 4f 72 6c 65 5a 5c 59 6c 62 6f 6d 6c 67 6c 49 69 4f 70 55 6f 4b 70 6f } //1 sOoDfftqwqaOrleZ\YlbomlglIiOpUoKpo
		$a_03_7 = {76 00 30 00 76 00 30 00 76 00 [0-10] 73 ?? 6f ?? 66 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 6c ?? 6f ?? 6c ?? 6c ?? 69 } //1
		$a_01_8 = {76 00 49 00 76 00 4e 00 76 00 53 00 76 00 54 00 76 00 41 00 76 00 4c 00 76 00 4c 00 76 00 3a 00 76 00 7c 00 } //1 vIvNvSvTvAvLvLv:v|
		$a_01_9 = {64 76 6f 76 77 76 6e 76 6c 76 6f 76 61 76 64 76 5f 76 66 76 61 76 69 76 6c 76 65 76 64 76 } //1 dvovwvnvlvovavdv_vfvavivlvevdv
		$a_03_10 = {26 6f 73 69 32 3d [0-05] 26 6f 73 69 31 3d [0-05] 26 61 73 3d [0-05] 26 66 77 3d [0-05] 26 61 76 3d } //1
		$a_03_11 = {26 6f 73 69 39 3d [0-05] 26 61 64 6d 69 6e 3d [0-05] 26 6c 61 73 74 65 72 72 6f 72 3d [0-05] 26 61 76 65 72 72 6f 72 3d } //1
		$a_01_12 = {6e 75 6d 73 3d 00 00 00 26 61 76 73 3d 31 } //1
		$a_01_13 = {70 61 63 6b 65 72 5f 74 79 70 65 76 65 72 73 69 6f 6e } //1 packer_typeversion
		$a_01_14 = {53 35 5f 00 46 34 62 5f } //1 㕓_㑆形
		$a_01_15 = {6d 76 79 76 6d 76 75 76 74 76 73 76 67 76 6c 76 77 76 6f 76 72 76 6b 76 } //1 mvyvmvuvtvsvgvlvwvovrvkv
		$a_00_16 = {00 2d 72 6e 61 6d 65 00 } //1 ⴀ湲浡e
		$a_00_17 = {00 2d 73 75 62 69 64 00 } //1 ⴀ畳楢d
		$a_00_18 = {00 2d 6e 6f 6a 73 00 } //1
		$a_00_19 = {0d 6e 6f 6a 73 00 } //1 渍橯s
		$a_01_20 = {d9 ee d9 c9 59 db f1 dd d9 76 0c } //1
		$a_01_21 = {41 56 4c 6f 6c 6c 69 70 6f 70 46 75 6e 63 40 40 } //1 AVLollipopFunc@@
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_03_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_03_10  & 1)*1+(#a_03_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_00_16  & 1)*1+(#a_00_17  & 1)*1+(#a_00_18  & 1)*1+(#a_00_19  & 1)*1+(#a_01_20  & 1)*1+(#a_01_21  & 1)*1) >=2
 
}