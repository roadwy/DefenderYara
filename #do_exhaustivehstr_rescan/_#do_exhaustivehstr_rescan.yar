
rule _#do_exhaustivehstr_rescan{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4d 65 63 61 4e 65 74 } //1 MecaNet
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_2{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {52 42 4e 4c 44 72 76 } //1 RBNLDrv
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_3{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4d 4e 4f 45 50 00 32 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_4{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4e 53 50 53 74 61 72 74 75 70 } //1 NSPStartup
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_5{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {40 67 5b 6f 4f 4e 5b 3f 75 21 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_6{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {5c 57 69 6e 42 75 64 67 65 74 5c } //1 \WinBudget\
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_7{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 45 4d 53 46 52 54 43 42 56 44 00 } //1 䔀卍剆䍔噂D
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_8{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 73 6e 41 67 65 6e 74 2e 64 6c 6c } //1 猀䅮敧瑮搮汬
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_9{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 41 4f 4c 54 6f 6f 6c 42 61 6e 64 } //1 IAOLToolBand
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_10{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {1b 4d f4 6a 08 68 00 68 c4 61 51 50 e8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_11{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {80 f9 41 7c 0d 80 f9 4d 7f 08 0f be c9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_12{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {85 db 74 0a 8a 06 32 c2 88 06 46 4b eb f2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_13{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 3e b3 15 cf a1 74 0b 4a 4e 83 fa 04 77 f1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_14{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_40_0 = {45 f8 08 da 89 fb 83 f9 09 0f 4e de 84 d2 00 } //10
	condition:
		((#a_40_0  & 1)*10) >=10
 
}
rule _#do_exhaustivehstr_rescan_15{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {70 70 74 78 3a 70 70 73 78 3a 67 73 66 3a 64 74 3a } //1 pptx:ppsx:gsf:dt:
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_16{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 33 0c 42 e8 ?? ?? ?? ?? 8a d8 [0-18] 88 18 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_17{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {7d 10 8b 85 ?? ?? ?? ?? 80 b4 28 ?? ?? ?? ?? ?? eb db } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_18{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2e 3f 41 56 49 45 55 72 6c 43 61 74 63 68 65 72 40 40 } //1 .?AVIEUrlCatcher@@
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_19{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4f 00 70 00 65 00 6e 00 43 00 61 00 6e 00 64 00 79 00 } //1 OpenCandy
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_20{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {75 05 66 33 c9 eb 04 66 b9 01 00 8b 44 24 08 66 89 0d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_21{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {f5 fe 00 00 00 c2 04 60 ff 9d e7 aa 04 60 ff 9d fb 12 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_22{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b8 00 04 00 00 31 d2 b9 36 07 03 00 f3 ab 8b 45 0c 6a 05 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_23{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {46 61 69 6c 65 64 20 6f 6e 20 53 74 61 72 74 2c 20 25 73 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_24{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2e 53 44 4b 2e 65 78 65 00 } //1
		$a_01_1 = {14 16 9a 26 16 2d f9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_rescan_25{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 7d f0 2a 7b 5a 13 0f 85 } //2
		$a_01_1 = {81 7d f4 2a 7b 5a 13 74 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}
rule _#do_exhaustivehstr_rescan_26{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {5c 56 43 20 50 72 6f 6a 65 63 74 5c 42 79 70 61 73 73 55 61 63 5c } //1 \VC Project\BypassUac\
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_27{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 73 6c 33 32 2e 64 6c 6c } //1 ssl32.dll
		$a_01_1 = {73 73 6c 36 34 2e 64 6c 6c } //1 ssl64.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_rescan_28{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2e 3f 41 56 43 57 69 6e 69 6e 65 74 5f 50 72 6f 74 6f 63 6f 6c 40 40 } //1 .?AVCWininet_Protocol@@
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_29{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {68 21 04 00 00 68 74 83 00 00 e8 dd e8 40 00 b8 30 99 19 b6 c2 08 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_30{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 4c 24 14 ff 53 53 53 53 8d 44 24 20 50 57 c7 44 24 28 80 69 67 ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_31{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 84 24 45 01 00 00 01 01 00 00 89 4e 20 66 0f 7f 46 10 66 0f 7f 06 56 e8 } //10
	condition:
		((#a_01_0  & 1)*10) >=1
 
}
rule _#do_exhaustivehstr_rescan_32{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 5d 6a 20 e8 } //1
		$a_01_1 = {45 78 63 6c 75 64 65 55 70 64 61 74 65 52 67 6e } //1 ExcludeUpdateRgn
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_rescan_33{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {43 6f 6e 66 69 67 50 61 6e 65 6c 2e 63 70 6c 00 43 50 6c 41 70 70 6c 65 74 00 } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}
rule _#do_exhaustivehstr_rescan_34{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d 08 6a 00 6a 00 50 8b 45 0c 6a 01 6a 00 6a 01 68 ff 01 0f 00 50 50 51 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_35{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4e 6f 74 65 70 61 64 50 6c 75 73 } //1 NotepadPlus
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_rescan_36{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 14 01 80 f2 9a 88 10 40 4e 75 f4 } //1
		$a_01_1 = {8a 14 08 90 f2 9a 88 11 41 4e 75 f4 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_37{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 00 6e 00 74 00 69 00 56 00 69 00 72 00 } //1 AntiVir
		$a_01_1 = {43 00 44 00 61 00 74 00 61 00 } //1 CData
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_rescan_38{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 85 84 fe ff ff 50 ff 15 ?? ?? ?? ?? 8d 4d 90 90 51 8d 55 fc 52 68 71 17 00 00 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_39{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b7 44 70 fe 33 c3 89 45 e4 3b 7d e4 7c 0f 8b 45 e4 05 ff 00 00 00 2b c7 89 45 e4 eb 03 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_40{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {56 4d 77 61 72 65 00 00 45 4d 55 4c 41 54 4f 52 00 00 00 00 56 69 72 74 75 61 6c 50 43 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_41{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {5c 68 75 75 68 77 69 74 68 77 61 6c 6c 65 74 5c 44 65 62 75 67 5c 68 75 75 68 2e 70 64 62 } //1 \huuhwithwallet\Debug\huuh.pdb
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_42{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 c2 8a 14 31 32 d0 88 14 31 } //1
		$a_01_1 = {8b 03 6a 00 81 c2 00 01 00 00 6a 00 52 50 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_rescan_43{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c6 45 f6 78 c6 45 f7 00 c7 44 24 0c ?? ?? ?? ?? c7 44 24 08 90 1b 00 8d 45 f3 89 44 24 04 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_44{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {50 72 6f 6a 65 63 74 31 2e 65 78 65 } //1 Project1.exe
		$a_01_1 = {4b 45 6e 63 72 79 70 74 69 6f 6e 46 75 6e 63 73 } //1 KEncryptionFuncs
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_rescan_45{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {85 c0 74 16 6a 32 ff d7 46 83 fe 05 72 da } //3
		$a_01_1 = {52 65 61 64 4f 6c 64 49 6e 69 46 69 6c 65 } //1 ReadOldIniFile
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}
rule _#do_exhaustivehstr_rescan_46{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 39 36 36 42 43 34 45 42 30 35 30 30 39 31 46 45 34 32 36 33 36 45 38 33 44 44 35 32 43 46 32 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_47{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 75 70 64 61 74 61 5c 73 70 6f 6f 6c 73 76 2e 65 78 65 } //1 C:\ProgramData\updata\spoolsv.exe
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_48{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 45 f0 8b 55 fc 0f b6 54 32 ff 32 d3 e8 ?? ?? ?? ?? 8b 55 f0 8d 45 f8 e8 ?? ?? ?? ?? 46 4f 75 df } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_49{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 65 74 43 6c 61 73 73 4c 6f 6e 67 41 } //1 SetClassLongA
		$a_01_1 = {4e 74 43 61 6c 6c 62 61 63 6b 52 65 74 75 72 6e } //1 NtCallbackReturn
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_rescan_50{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f be 84 04 ?? ?? ?? ?? 35 ?? ?? ?? ?? 88 c1 8b ?? ?? ?? ?? ?? ?? 88 ?? ?? ?? ?? ?? ?? c7 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? ?? 83 c0 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_51{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 0e 88 59 ?? b9 ?? ?? ?? ?? 2b c8 8b d7 8a 1c 01 80 f3 ?? 88 18 40 4a 75 f4 57 8b ce } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_52{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 4d 5f 25 90 09 03 00 81 7d } //1
		$a_03_1 = {e8 86 74 0e 90 09 05 00 81 7d ?? 52 90 90 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_53{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {73 79 73 30 90 0f 04 00 2e 64 6c 6c 00 } //1
		$a_03_1 = {73 79 73 30 90 0f 04 00 2e 61 64 64 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_rescan_54{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c6 45 f9 70 c6 45 fa 65 c6 45 fb 6e 88 5d fc c6 45 ec 73 c6 45 ed 68 c6 45 ee 65 c6 45 ef 6c c6 45 f0 6c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_55{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 4e 1c ff 75 08 41 51 50 89 46 0c e8 } //1
		$a_01_1 = {6c 00 6e 00 6b 00 00 00 5c 00 2a 00 2e 00 2a 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_rescan_56{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2e 3f 41 56 43 49 45 43 6f 6d 48 6f 6f 6b 65 72 40 45 78 70 6c 6f 72 65 72 40 53 70 65 65 64 42 69 74 40 40 } //1 .?AVCIEComHooker@Explorer@SpeedBit@@
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_57{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {85 c0 0f 85 fa 00 00 00 8b 4f 48 8d 77 48 8b 41 f8 85 c0 75 1b 8d 4c 24 08 c7 84 24 1c 02 00 00 ff ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_58{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 8d 5c ff ff ff 89 41 0c c7 45 fc 7a 00 00 00 8d 55 d4 52 6a 00 ff 15 ?? ?? ?? ?? c7 45 fc 7b 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_59{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {ec f5 24 b0 30 a6 52 61 e3 05 9c 48 ab 9e 1e cb } //1
		$a_01_1 = {23 43 23 54 34 67 23 89 c5 a4 84 34 95 37 85 b6 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_rescan_60{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 30 45 31 30 35 34 42 2d 30 31 45 45 2d 34 44 35 37 2d 41 30 35 39 2d 34 44 39 39 46 33 33 39 37 30 39 46 7d } //1 A0E1054B-01EE-4D57-A059-4D99F339709F}
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_61{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5c 72 75 73 74 64 65 73 6b 2e 65 78 65 } //1 \rustdesk.exe
		$a_01_1 = {73 74 64 5c 73 72 63 5c 69 6f 5c 63 75 72 73 6f 72 2e 72 73 } //1 std\src\io\cursor.rs
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_rescan_62{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 00 32 01 8b 4d 08 03 4d f8 88 01 8b 45 fc 40 89 45 fc 8b 45 10 03 45 14 39 45 fc 72 08 8b 45 10 89 45 f4 eb 06 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_63{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 50 02 66 8b 08 83 c0 02 66 3b cf 75 f5 2b c2 d1 f8 8b c8 74 1b 8d 04 4e 66 83 78 fe 5c 74 0f 6a 5c 5a 66 89 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_64{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b0 f3 b6 a8 ce c4 bc fe d6 d0 a3 ac b6 c1 c8 a1 b5 da d2 bb b8 f6 d2 aa b0 f3 b6 a8 ce c4 bc fe ca b1 b3 f6 b4 ed 21 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_65{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 04 06 88 45 ?? 8b 45 ?? 8a 14 16 88 14 06 8b 45 ?? 8a 55 ?? 88 14 06 ff 45 ?? 81 7d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_66{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_81_0 = {5c 62 69 6e 5c 55 6e 69 6e 73 74 61 6c 6c 4d 61 6e 61 67 65 72 5c 55 6e 69 6e 73 74 61 6c 6c 4d 61 6e 61 67 65 72 2e 70 64 62 } //1 \bin\UninstallManager\UninstallManager.pdb
	condition:
		((#a_81_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_67{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {43 00 58 00 53 00 61 00 6c 00 76 00 61 00 74 00 69 00 6f 00 6e 00 3a 00 3a 00 53 00 61 00 6c 00 45 00 6e 00 61 00 62 00 6c 00 65 00 } //1 CXSalvation::SalEnable
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_68{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {52 61 77 53 6f 63 6b 65 74 33 32 2e 64 6c 6c 00 52 75 6e 00 } //1 慒卷捯敫㍴⸲汤l畒n
		$a_01_1 = {52 61 77 53 6f 63 6b 65 74 36 34 2e 64 6c 6c 00 52 75 6e 00 } //1 慒卷捯敫㙴⸴汤l畒n
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_69{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 37 7e 13 a4 e8 } //1
		$a_01_1 = {68 44 6a 01 b9 } //1
		$a_01_2 = {68 b3 26 b8 77 } //1
		$a_01_3 = {68 ac c8 33 2e } //1
		$a_01_4 = {53 4e 46 49 52 4e 57 } //2 SNFIRNW
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2) >=2
 
}
rule _#do_exhaustivehstr_rescan_70{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6a 00 63 00 6c 00 2e 00 73 00 76 00 6e 00 2e 00 73 00 6f 00 75 00 72 00 63 00 65 00 66 00 6f 00 72 00 67 00 65 00 2e 00 6e 00 65 00 74 00 } //1 jcl.svn.sourceforge.net
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_71{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {be 65 00 00 00 6a 0a e8 ?? ?? ff ff 6a 00 6a 00 6a 00 6a 08 e8 ?? ?? ff ff 6a 00 6a 02 6a 00 6a 08 e8 ?? ?? ff ff 4e 75 dc } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_72{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 75 72 6c 5f 73 68 61 72 65 5f 69 6e 69 74 } //1 curl_share_init
		$a_01_1 = {56 69 72 74 75 61 6c 51 75 65 72 79 } //1 VirtualQuery
		$a_01_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule _#do_exhaustivehstr_rescan_73{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {69 6e 76 61 6c 69 64 21 00 6b 72 6e 6c 6e 2e 66 6e 72 00 50 61 74 68 00 53 6f 66 74 77 61 72 65 5c 46 6c 79 53 6b 79 5c 45 5c 49 6e 73 74 61 6c 6c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_74{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2e 64 6c 6c 00 53 65 72 76 69 63 65 4d 61 69 6e 00 00 } //1
		$a_01_1 = {72 70 63 61 70 3a 2f 2f 00 00 00 00 45 6e 61 62 6c 65 46 69 72 65 77 61 6c 6c 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_rescan_75{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {59 00 64 00 72 00 53 00 75 00 70 00 70 00 } //1 YdrSupp
		$a_01_1 = {2d 00 2d 00 75 00 73 00 65 00 72 00 2d 00 64 00 61 00 74 00 61 00 2d 00 64 00 69 00 72 00 3d 00 } //1 --user-data-dir=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_rescan_76{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {65 6e 64 61 67 75 79 2e 70 64 62 00 } //1
		$a_01_1 = {66 61 74 68 65 72 69 61 72 74 2e 70 64 62 00 } //1
		$a_01_2 = {64 66 73 66 67 6a 66 67 64 65 73 2e 70 64 62 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_77{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6d 65 74 73 72 76 2e 64 6c 6c 00 00 52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 } //1
		$a_01_1 = {5f 52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 40 30 } //1 _ReflectiveLoader@0
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_rescan_78{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {10 75 2b 09 1d ?? ?? ?? 10 83 65 fc 00 8d 45 ?? 50 8d 45 ?? 50 b9 ?? ?? ?? 10 e8 ?? ?? ff ff 68 ?? ?? ?? 10 e8 ?? ?? ?? 00 83 4d fc ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_79{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 44 00 61 00 74 00 61 00 4d 00 6e 00 67 00 72 00 } //1 Software\DataMngr
		$a_01_1 = {41 70 70 72 6f 76 65 49 45 41 64 64 6f 6e } //1 ApproveIEAddon
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_80{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2e 3f 41 56 3f 24 5f 52 65 66 5f 63 6f 75 6e 74 40 56 42 48 4f 55 70 64 61 74 65 72 43 6f 6d 70 6f 6e 65 6e 74 73 46 61 63 74 6f 72 79 40 40 40 73 74 64 40 40 } //1 .?AV?$_Ref_count@VBHOUpdaterComponentsFactory@@@std@@
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_81{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {4d 4f 44 5f 47 45 54 53 43 52 45 45 4e } //1 MOD_GETSCREEN
		$a_01_1 = {4d 4f 44 5f 43 4f 4d 50 41 43 54 41 5f 49 4d 47 } //1 MOD_COMPACTA_IMG
		$a_01_2 = {4d 4f 44 5f 6d 4f 74 68 65 72 42 72 6f 77 73 65 72 } //1 MOD_mOtherBrowser
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_rescan_82{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {63 6f 64 65 73 6f 66 74 20 70 77 20 73 74 65 61 6c 65 72 } //1 codesoft pw stealer
		$a_01_1 = {5c 70 77 66 69 6c 65 2e 6c 6f 67 00 } //1
		$a_01_2 = {5c 6c 6f 67 65 6e 63 72 79 70 74 2e 6c 6f 67 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_rescan_83{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 f8 01 75 08 53 68 48 50 45 00 eb db 83 f8 02 } //1
		$a_01_1 = {75 27 80 7e 01 74 75 21 80 7e 02 74 75 1b 80 7e 03 70 75 15 80 7e 04 3a 75 0f 80 7e 05 2f 75 09 80 7e 06 2f } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_84{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 00 61 00 6e 00 74 00 61 00 62 00 6c 00 6f 00 71 00 64 00 61 00 74 00 61 00 } //1 santabloqdata
		$a_01_1 = {76 00 65 00 72 00 64 00 65 00 62 00 6c 00 6f 00 71 00 64 00 61 00 74 00 61 00 } //1 verdebloqdata
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_85{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5d 5d 3e 3c 2f 75 72 69 3e } //1 ]]></uri>
		$a_01_1 = {5d 5d 3e 3c 2f 63 6c 69 63 6b 75 72 6c 3e } //1 ]]></clickurl>
		$a_01_2 = {64 65 67 65 6e 65 72 61 74 69 76 65 2b 6a 6f 69 6e 74 2b 64 69 73 65 61 73 65 } //1 degenerative+joint+disease
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule _#do_exhaustivehstr_rescan_86{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4e 28 03 4d ?? 53 6a 11 68 ?? ?? ?? ?? 50 ff 75 08 89 0d ?? ?? ?? ?? ff d7 } //1
		$a_03_1 = {8b 4f 28 03 4d ?? 53 6a 11 68 ?? ?? ?? ?? 50 ff 75 08 89 0d ?? ?? ?? ?? ff d6 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_87{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 25 73 } //1 SYSTEM\CurrentControlSet\Services\%s
		$a_00_1 = {00 48 41 43 4b } //1
		$a_00_2 = {6e 65 74 73 76 63 73 5f 30 78 25 } //1 netsvcs_0x%
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule _#do_exhaustivehstr_rescan_88{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {80 3c 03 2e 0f 94 c0 0f b6 c0 01 45 d0 43 39 fb 72 eb } //1
		$a_03_1 = {80 38 7c 0f 85 f0 02 00 00 c6 00 00 c7 05 ?? ?? 40 00 00 00 00 00 83 3d ?? ?? 40 00 02 0f 8f 9c 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_rescan_89{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {61 00 62 00 6f 00 75 00 74 00 3a 00 73 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 72 00 69 00 73 00 6b 00 00 00 } //1
		$a_01_1 = {25 73 5c 70 61 79 66 6f 72 6d 5f 25 30 32 64 2e 25 30 32 64 2e } //1 %s\payform_%02d.%02d.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_rescan_90{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2e 00 72 00 67 00 2e 00 72 00 6f 00 } //1 .rg.ro
		$a_01_1 = {53 00 74 00 61 00 6e 00 64 00 61 00 6c 00 6f 00 6e 00 65 00 20 00 6d 00 75 00 73 00 74 00 20 00 62 00 65 00 20 00 2e 00 65 00 78 00 65 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_rescan_91{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d a4 05 61 09 74 0e 6a 00 8b 45 08 50 } //1
		$a_01_1 = {44 00 00 00 6e 00 00 00 7c 00 00 00 7f 00 00 00 91 00 00 00 00 00 90 01 00 00 50 00 00 00 50 00 00 00 10 00 00 00 10 00 00 00 20 00 9b 85 e7 e3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_92{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {08 b7 7a 5c 56 19 34 e0 89 08 b0 3f 5f 7f 11 d5 0a 3a 08 06 15 12 81 } //1
		$a_01_1 = {2a 2a 32 49 33 20 2e 40 37 61 33 2e 20 20 20 20 34 d5 3a 48 20 2e 20 20 20 2e 34 de 36 2d 6b 34 2e 33 7b 31 2a 2b } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_rescan_93{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 00 68 00 65 00 6c 00 6c 00 5c 00 6f 00 70 00 65 00 6e 00 5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 00 00 00 00 22 00 20 00 2d 00 61 00 20 00 22 00 25 00 31 00 22 00 20 00 25 00 2a 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_94{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 0f b6 00 8b d0 80 e2 0f 88 55 ff 24 f0 0f b6 c0 c1 e8 04 (eb ?? e9 ??|?? ?? ?? 00) 00 00 00 } //1
		$a_03_1 = {8b fa 4f 85 ff 0f 8c ?? ?? ?? ?? 47 33 ed e9 ?? ?? ?? ?? 00 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_95{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 6f 6e 74 72 6f 6c 50 61 6e 65 6c 43 70 6c 2e 63 70 6c 00 } //1
		$a_01_1 = {10 cb 43 70 6c 00 1c f2 50 73 41 50 49 00 } //1
		$a_01_2 = {70 64 6c 6c 69 6e 73 74 61 6c 65 72 2e 64 6c 6c 00 69 6e 73 74 61 6c 6c 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=2
 
}
rule _#do_exhaustivehstr_rescan_96{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {46 74 70 50 75 74 46 69 6c 65 41 00 } //1 瑆偰瑵楆敬A
		$a_01_1 = {52 65 67 53 65 74 56 61 6c 75 65 45 78 41 00 } //1
		$a_01_2 = {53 69 7a 65 6f 66 52 65 73 6f 75 72 63 65 00 } //1
		$a_01_3 = {52 74 6c 4d 6f 76 65 4d 65 6d 6f 72 79 00 } //1 瑒䵬癯䵥浥牯y
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule _#do_exhaustivehstr_rescan_97{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 20 00 54 00 6f 00 6f 00 6c 00 00 00 ?? ?? ?? ?? ff ff ff ff 0d 00 00 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 20 00 54 00 6f 00 6f 00 6c 00 00 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_98{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {fb 12 fc 0d 6c 6c ff 80 0c 00 fc a0 00 0c 6c 6c ff 6c 5c ff e0 1c 5c 01 00 15 } //1
		$a_00_1 = {53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 00 } //1
		$a_01_2 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule _#do_exhaustivehstr_rescan_99{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {2e 53 74 6f 6e 65 00 } //1
		$a_01_1 = {75 f4 8b 15 38 d7 41 00 8b 0d 3c d7 41 00 89 10 8b 15 40 d7 41 00 89 48 04 66 8b 0d 44 d7 41 00 89 50 08 8b 15 a4 63 42 00 52 66 89 48 0c 8d 84 24 20 03 00 00 68 48 d7 41 00 50 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_100{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 53 45 6e 67 69 6e 65 2e 64 6c 6c 00 } //1
		$a_01_1 = {43 72 65 61 74 65 53 53 45 6e 67 69 6e 65 49 6e 74 65 72 66 61 63 65 00 } //1 牃慥整卓湅楧敮湉整晲捡e
		$a_01_2 = {52 65 6c 65 61 73 65 53 53 45 6e 67 69 6e 65 49 6e 74 65 72 66 61 63 65 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_rescan_101{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {4e 6f 74 65 70 61 64 50 6c 75 73 } //1 NotepadPlus
		$a_00_1 = {73 00 61 00 6b 00 75 00 72 00 61 00 } //1 sakura
		$a_01_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_01_3 = {44 65 6c 65 74 65 46 69 6c 65 41 } //1 DeleteFileA
		$a_01_4 = {43 72 65 61 74 65 46 69 6c 65 41 } //1 CreateFileA
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}
rule _#do_exhaustivehstr_rescan_102{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {7b 42 37 30 34 35 36 45 32 2d 32 33 38 38 2d 34 41 30 39 2d 41 45 43 34 2d 46 35 33 43 46 32 31 36 41 44 41 45 7d } //1 {B70456E2-2388-4A09-AEC4-F53CF216ADAE}
		$a_01_1 = {53 79 73 74 65 6d 52 65 67 69 73 74 65 72 00 00 } //1
		$a_01_2 = {53 75 70 65 72 41 44 2e 64 6c 6c 00 } //1 畓数䅲⹄汤l
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_rescan_103{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 6c 69 63 6b 20 54 6f 20 78 3a 20 25 64 20 79 3a 20 25 64 } //2 Click To x: %d y: %d
		$a_01_1 = {69 6e 76 61 6c 69 64 5f 73 63 68 65 64 75 6c 65 72 5f 70 6f 6c 69 63 79 5f 6b 65 79 } //1 invalid_scheduler_policy_key
		$a_01_2 = {56 43 57 69 6e 64 6f 77 43 6f 6e 74 72 6f 6c 6c 65 72 } //1 VCWindowController
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_rescan_104{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3c 2b 90 75 06 90 83 c2 3e 90 43 3c 2f 90 75 06 90 83 c2 3f 90 43 3c 30 90 7c 0a 3c 39 90 7f 05 04 04 03 d0 43 } //1
		$a_01_1 = {3c 41 90 7c 0b 3c 5a 90 7f 06 2c 41 90 03 d0 43 3c 61 90 7c 0a 3c 7a 90 7f 05 2c 47 03 d0 43 c1 c2 06 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_rescan_105{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 45 14 8b d8 c7 03 d4 01 00 00 33 c0 89 43 04 33 c0 89 43 08 33 c0 89 43 0c } //1
		$a_01_1 = {4d 00 41 00 49 00 4e 00 49 00 43 00 4f 00 4e 00 00 00 00 00 75 00 70 00 00 00 } //1
		$a_01_2 = {2e 63 70 6c 00 43 50 6c 41 70 70 6c 65 74 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule _#do_exhaustivehstr_rescan_106{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {54 00 54 00 57 00 4f 00 42 00 52 00 4f 00 } //5 TTWOBRO
		$a_01_1 = {54 74 77 6f 62 72 6f 06 74 77 6f 62 72 6f } //5 瑔潷牢ٯ睴扯潲
		$a_01_2 = {55 43 61 72 72 65 67 61 6e 64 6f 00 } //1 䍕牡敲慧摮o
		$a_01_3 = {55 56 65 72 69 66 69 63 61 00 } //1 噕牥晩捩a
		$a_01_4 = {55 46 75 6e 63 6f 65 73 00 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}
rule _#do_exhaustivehstr_rescan_107{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {64 00 65 00 66 00 61 00 75 00 6c 00 74 00 5f 00 73 00 65 00 61 00 72 00 63 00 68 00 5f 00 70 00 72 00 6f 00 76 00 69 00 64 00 65 00 72 00 00 00 } //1
		$a_01_1 = {5c 52 65 6c 65 61 73 65 5c 44 65 66 61 75 6c 74 50 61 63 6b 2e 70 64 62 } //1 \Release\DefaultPack.pdb
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_rescan_108{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_1 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //1 CreateRemoteThread
		$a_00_2 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 } //1 LoadResource
		$a_03_3 = {55 8b ec 83 c4 f0 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? e9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}
rule _#do_exhaustivehstr_rescan_109{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {5c 55 73 65 72 73 5c 31 5c [0-40] 5c 52 61 69 6e 6d 65 74 65 72 2e 70 64 62 } //1
		$a_01_1 = {52 00 61 00 69 00 6e 00 6d 00 65 00 74 00 65 00 72 00 2e 00 69 00 6e 00 69 00 20 00 6e 00 6f 00 74 00 20 00 66 00 6f 00 75 00 6e 00 64 00 } //1 Rainmeter.ini not found
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_110{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {eb 03 8d 49 00 8a 1c 17 32 5c 29 01 41 88 1a 42 3b ce 72 f1 } //1
		$a_01_1 = {40 88 54 28 ff 3b c1 72 eb } //1
		$a_03_2 = {8d a4 24 00 00 00 00 [0-05] 8a 90 90 ?? ?? 00 10 32 90 90 ?? ?? 00 10 40 88 94 04 ?? ?? 00 00 3b c6 72 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_111{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {7f 22 8b 45 fc 99 f7 3d ?? ?? ?? ?? 8b 45 08 03 45 fc 8a 08 32 8a ?? ?? ?? ?? 8b 55 08 03 55 fc 88 0a eb cd } //1
		$a_03_1 = {79 08 49 81 c9 00 ff ff ff 41 8b 45 08 03 45 ?? 8a 10 32 94 8d ?? ?? ?? ?? 8b 45 08 03 45 ?? 88 10 e9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_rescan_112{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {52 65 67 69 73 74 72 61 74 69 6f 6e 49 44 ?? ?? 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e } //1
		$a_01_1 = {f7 d8 1b c0 83 e0 f3 83 c0 0d eb 03 6a 57 58 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_rescan_113{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_41_0 = {7d 10 85 ff 0f 84 ab 00 00 00 8b 55 0c 8a 02 88 44 35 e5 46 83 fe 03 75 e0 8a 55 e5 88 d0 c0 e8 02 88 45 e1 83 e2 03 c1 e2 04 8a 4d e6 c0 e9 04 01 ca 88 55 e2 8a 4d e6 83 e1 0f 8a 55 e7 c0 ea 06 8d 14 8a 88 55 e3 8a 55 e7 83 e2 3f 88 55 e4 31 ff 00 } //1
	condition:
		((#a_41_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_114{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 8a 44 18 ff 24 0f 8b 55 f8 8a 54 32 ff 80 e2 0f 32 c2 88 45 ?? 8d 45 fc e8 ?? ?? ?? ?? 8b 55 fc 8a 54 1a ff 80 e2 f0 8a 4d ?? 02 d1 88 54 18 ff } //1
		$a_03_1 = {b8 00 00 00 00 40 3d 00 e9 a4 35 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 75 e9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_115{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {43 6f 6d 70 75 74 61 64 6f 72 2e 2e } //1 Computador..
		$a_01_1 = {4c 6f 67 69 6e 4e 61 6d 65 } //1 LoginName
		$a_01_2 = {53 65 6e 68 61 } //1 Senha
		$a_01_3 = {6a 61 76 61 73 63 72 69 70 74 } //1 javascript
		$a_01_4 = {61 62 6f 75 74 3a 62 6c 61 6e 6b } //1 about:blank
		$a_01_5 = {4d 61 67 65 6c 6c 61 6e 20 4d 53 57 48 45 45 4c } //5 Magellan MSWHEEL
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*5) >=8
 
}
rule _#do_exhaustivehstr_rescan_116{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_01_0 = {77 65 62 73 61 66 65 5c 57 65 62 53 61 66 65 50 6c 75 67 69 6e 2e 70 64 62 } //1 websafe\WebSafePlugin.pdb
		$a_01_1 = {5c 44 61 74 61 4d 6e 67 72 55 49 2e 70 64 62 } //1 \DataMngrUI.pdb
		$a_01_2 = {5c 53 68 6f 70 70 65 72 50 72 6f 2e 70 64 62 } //1 \ShopperPro.pdb
		$a_01_3 = {54 6f 6f 6c 73 3a 3a 49 45 54 6f 6f 6c 73 3a 3a 60 } //1 Tools::IETools::`
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_117{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 72 63 5c 75 6e 69 63 6f 64 65 5c 70 72 69 6e 74 61 62 6c 65 2e 72 73 } //1 src\unicode\printable.rs
		$a_01_1 = {72 75 73 74 5f 70 61 6e 69 63 } //1 rust_panic
		$a_01_2 = {73 72 63 2f 6d 61 69 6e 2e 72 73 } //1 src/main.rs
		$a_01_3 = {66 66 69 5c 63 5f 73 74 72 2e 72 73 } //1 ffi\c_str.rs
		$a_01_4 = {73 74 72 5c 70 61 74 74 65 72 6e 2e 72 73 } //1 str\pattern.rs
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule _#do_exhaustivehstr_rescan_118{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 4c 00 6f 00 77 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 53 00 65 00 61 00 72 00 63 00 68 00 20 00 50 00 72 00 6f 00 74 00 65 00 63 00 74 00 69 00 6f 00 6e 00 } //1 SOFTWARE\AppDataLow\Software\Search Protection
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_119{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {28 73 6f 63 6b 73 7c 68 74 74 70 29 3d 28 5b 5e 3a 5d 2b 29 3a 28 5c 64 2b 29 00 } //1
		$a_01_1 = {55 43 46 47 5f 54 48 52 45 41 44 5f 53 54 41 43 4b 5f 53 49 5a 45 00 } //1
		$a_01_2 = {7b 22 69 64 22 3a 20 30 2c 20 22 72 65 73 75 6c 74 22 3a 20 7b 22 64 61 74 61 22 3a 20 22 30 30 30 30 } //1 {"id": 0, "result": {"data": "0000
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule _#do_exhaustivehstr_rescan_120{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2f 73 72 63 2f 67 69 74 68 75 62 2e 63 6f 6d 2f 74 33 72 6d 31 6e 34 6c 2f 6d 65 67 61 63 6d 64 2f 6d 61 69 6e 2e 67 6f } //1 /src/github.com/t3rm1n4l/megacmd/main.go
		$a_01_1 = {2f 73 72 63 2f 67 69 74 68 75 62 2e 63 6f 6d 2f 74 33 72 6d 31 6e 34 6c 2f 6d 65 67 61 63 6d 64 2f 63 6c 69 65 6e 74 2f 63 6c 69 65 6e 74 2e 67 6f } //1 /src/github.com/t3rm1n4l/megacmd/client/client.go
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_rescan_121{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 00 6c 00 65 00 61 00 72 00 4c 00 6f 00 63 00 6b 00 } //1 ClearLock
		$a_01_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 62 00 6f 00 6f 00 74 00 2d 00 6c 00 61 00 6e 00 64 00 2e 00 6e 00 65 00 74 00 2f 00 } //1 http://www.boot-land.net/
		$a_01_2 = {49 00 61 00 6d 00 4d 00 72 00 2e 00 45 00 64 00 21 00 } //1 IamMr.Ed!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_rescan_122{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 72 6f 73 73 72 69 64 65 72 41 70 70 30 30 35 31 36 38 30 } //1 CrossriderApp0051680
		$a_01_1 = {43 72 6f 73 73 72 69 64 65 72 41 70 70 30 30 35 31 36 38 32 } //1 CrossriderApp0051682
		$a_01_2 = {43 72 6f 73 73 72 69 64 65 72 41 70 70 30 30 35 31 36 38 34 } //1 CrossriderApp0051684
		$a_01_3 = {2e 3f 41 56 43 43 72 6f 73 73 52 69 64 65 72 4c 6f 67 67 65 72 40 40 } //1 .?AVCCrossRiderLogger@@
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_123{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {c7 45 f4 01 00 00 00 8b 45 fc 8b 55 f4 33 db 8a 5c 10 ff 03 5d f8 8b c3 33 d2 52 50 8d 45 e8 e8 ?? ?? ?? ?? 8b 45 e8 e8 } //1
		$a_03_1 = {64 ff 35 00 00 00 00 64 89 25 00 00 00 00 58 c3 e9 90 09 05 00 68 } //1
		$a_03_2 = {2e 63 61 62 00 00 ff ff ff ff 0a 00 00 00 ?? ?? ?? ?? ?? ?? 2e 63 61 62 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_124{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {54 00 6a 00 65 00 66 00 43 00 62 00 73 00 5d 00 50 00 66 00 6e 00 44 00 76 00 74 00 75 00 70 00 6e 00 55 00 69 00 66 00 6e 00 66 00 } //1 TjefCbs]PfnDvtupnUifnf
		$a_01_1 = {74 00 7a 00 74 00 75 00 66 00 6e 00 34 00 33 00 5d 00 } //1 tztufn43]
		$a_01_2 = {51 00 73 00 70 00 68 00 73 00 62 00 6e 00 21 00 47 00 6a 00 6d 00 66 00 74 00 } //1 Qsphsbn!Gjmft
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_rescan_125{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {b8 54 4c 55 00 e8 ?? 40 14 00 6a 04 58 e8 ?? 0c 13 00 56 8b f1 89 75 f0 } //1
		$a_01_1 = {68 50 61 5c 00 8d 8d 38 ff ff ff 89 5d f0 e8 0e 0c 00 00 8d 85 38 ff ff ff 50 8d 45 9c } //1
		$a_01_2 = {8b 45 90 03 c0 89 45 90 8b 45 94 03 c0 89 45 94 33 c0 8a 88 e0 16 5c 00 88 4c 05 ac 40 3a cb } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_126{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } //1 \\.\PhysicalDrive0
		$a_01_1 = {64 00 6c 00 6c 00 68 00 6f 00 73 00 74 00 2e 00 64 00 61 00 74 00 } //1 dllhost.dat
		$a_01_2 = {66 00 73 00 75 00 74 00 69 00 6c 00 20 00 75 00 73 00 6e 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 6a 00 6f 00 75 00 72 00 6e 00 61 00 6c 00 20 00 2f 00 44 00 } //1 fsutil usn deletejournal /D
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule _#do_exhaustivehstr_rescan_127{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 00 3f 00 49 00 53 00 4f 00 2d 00 38 00 38 00 35 00 39 00 2d 00 31 00 3f 00 51 00 3f 00 } //1 =?ISO-8859-1?Q?
		$a_01_1 = {76 00 62 00 53 00 65 00 6e 00 64 00 4d 00 61 00 69 00 6c 00 } //1 vbSendMail
		$a_01_2 = {49 00 6e 00 76 00 61 00 6c 00 69 00 64 00 20 00 42 00 63 00 63 00 3a 00 20 00 52 00 65 00 63 00 69 00 70 00 69 00 65 00 6e 00 74 00 } //1 Invalid Bcc: Recipient
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule _#do_exhaustivehstr_rescan_128{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {50 6a 00 6a 00 6a 1c 6a 00 ff 15 ?? ?? ?? ?? 68 04 01 00 00 8d 85 ?? ?? ?? ?? 6a 00 50 e8 ?? ?? ?? ?? 83 c4 ?? c7 85 ?? ?? ?? ?? ?? ?? ?? ?? 8d 8d ?? ?? ?? ?? c7 85 ?? ?? ?? ?? 00 00 00 00 c6 85 ?? ?? ?? ?? 00 6a 18 68 } //1
		$a_01_1 = {75 5f 62 72 6f 77 73 65 72 53 65 74 74 69 6e 67 73 49 6e 73 74 61 6c 6c 65 72 } //1 u_browserSettingsInstaller
		$a_01_2 = {68 6f 6d 65 2b 73 74 61 72 74 75 70 } //1 home+startup
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_129{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 01 0f b6 1e 8b d0 c1 ea 18 33 d3 0f b6 59 07 c1 e0 08 0b c3 c1 e2 02 33 82 ?? ?? ?? ?? 46 89 01 8b 41 04 c1 e0 08 33 82 ?? ?? ?? ?? 4f 89 41 04 } //1
		$a_01_1 = {49 bb 00 80 c1 2a 21 4e 62 fe 49 03 cb 48 b8 bd 42 7a e5 d5 94 bf d6 48 f7 e1 48 83 c8 ff 48 c1 ea 17 48 81 fa 7f d2 ff 7f 48 0f 4f d0 } //1
		$a_01_2 = {45 6e 61 62 6c 65 45 55 44 43 } //1 EnableEUDC
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_rescan_130{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {6e 74 56 65 72 73 69 6f 6e 5c 70 6f 6c 69 63 00 69 65 73 5c 45 78 70 6c 6f 72 65 72 5c 52 75 6e } //1 瑮敖獲潩屮潰楬c敩屳硅汰牯牥剜湵
		$a_00_1 = {25 73 73 79 73 6f 70 74 69 6f 6e 2e 69 6e 69 00 2e 74 6d 70 } //1
		$a_02_2 = {41 6c 77 61 79 73 [0-0a] 5c 72 75 6e 64 6c 6c 33 32 [0-08] 74 6d 70 [0-06] 2d 75 [0-06] 2d 65 00 53 48 47 65 74 46 6f 6c 64 65 72 50 61 74 68 41 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_rescan_131{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {24 00 5f 00 5f 00 53 00 49 00 47 00 26 00 6f 00 76 00 72 00 3d 00 24 00 5f 00 5f 00 4f 00 56 00 52 00 26 00 61 00 6d 00 69 00 67 00 6f 00 3d 00 } //1 $__SIG&ovr=$__OVR&amigo=
		$a_01_1 = {2f 00 6e 00 6f 00 74 00 69 00 66 00 69 00 63 00 61 00 74 00 65 00 2e 00 70 00 68 00 70 00 3f 00 64 00 69 00 64 00 3d 00 } //1 /notificate.php?did=
		$a_01_2 = {2e 00 64 00 61 00 74 00 3f 00 64 00 69 00 64 00 3d 00 } //1 .dat?did=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule _#do_exhaustivehstr_rescan_132{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 05 53 8d 45 b4 50 8d 45 f4 50 ff 75 fc ff 15 ?? ?? ?? ?? 83 7d bc 3c ff 75 fc 0f 84 cc 00 00 00 ff 15 } //1
		$a_01_1 = {5c 00 3f 00 3f 00 5c 00 7a 00 3a 00 5c 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00 00 00 00 00 5c 00 3f 00 3f 00 5c 00 7a 00 3a 00 5c 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 65 00 78 00 65 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_rescan_133{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_03_0 = {81 e1 0f 00 00 80 79 05 49 83 c9 f0 41 (8b [0-02] 88 4d ?? 8a 4c 38 02 32 cb 8a 14 3|0 32 d3 )} //10
		$a_03_1 = {81 e1 0f 00 00 80 79 05 49 83 c9 f0 41 8b [0-02] 88 4d ?? 8a 4c 38 02 32 cb } //10
		$a_03_2 = {25 0f 00 00 80 79 05 48 83 c8 f0 40 88 45 ?? (8b 45 08 03 45 f8 0f b6 00 0f b6 4d ff 33 c1|8a 01 8a d0 32 d3) } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_03_2  & 1)*10) >=10
 
}
rule _#do_exhaustivehstr_rescan_134{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {58 58 58 00 } //1 塘X
		$a_00_1 = {58 00 58 00 53 00 30 00 53 00 00 00 } //1
		$a_00_2 = {58 58 53 32 53 00 } //1 塘㉓S
		$a_00_3 = {58 58 53 33 53 00 } //1 塘㍓S
		$a_01_4 = {8b 85 44 fe ff ff 8d 8d 48 fe ff ff ba e0 45 03 10 e8 aa ff fe ff 33 c0 5a 59 59 64 89 10 68 50 45 03 10 8d 85 44 fe ff ff e8 3e 07 fd ff 8d 85 58 fe ff ff ba 07 00 00 00 e8 9a 00 fd ff 8d 85 74 fe ff ff ba 02 00 00 00 e8 36 07 fd ff } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule _#do_exhaustivehstr_rescan_135{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 05 00 00 "
		
	strings :
		$a_01_0 = {61 70 70 6c 69 63 61 74 69 6f 6e 2f 6a 73 6f 6e 64 72 69 76 65 73 2f 7b 64 72 69 76 65 49 64 7d } //5 application/jsondrives/{driveId}
		$a_01_1 = {73 68 65 65 74 73 2e 67 6f 6f 67 6c 65 61 70 69 73 2e 63 6f 6d } //5 sheets.googleapis.com
		$a_01_2 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 } //1 Go build ID: "
		$a_01_3 = {47 4f 44 45 42 55 47 3a 20 75 6e 6b 6e 6f 77 6e 20 63 70 75 20 66 65 61 74 75 72 65 } //1 GODEBUG: unknown cpu feature
		$a_01_4 = {47 6f 20 62 75 69 6c 64 69 6e 66 3a } //1 Go buildinf:
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=11
 
}
rule _#do_exhaustivehstr_rescan_136{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 65 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 5c } //1 Software\Microsoft\Windows\CurrentVersion\explorer\Browser Helper Objects\
		$a_01_1 = {31 d2 f7 f1 4e 80 c2 30 80 fa 3a 72 03 80 c2 07 88 16 09 c0 75 ea 59 5a 29 f1 29 ca 76 10 01 d1 b0 30 29 d6 eb 03 88 04 32 4a 75 fa 88 06 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_rescan_137{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2a 2e 64 6f 63 2c 2a 2e 64 6f 63 78 2c 2a 2e 64 6f 63 6d 2c 2a 2e 6f 64 74 2c 2a 2e 78 6c 73 2c 2a 2e 78 6c 73 78 2c 2a 2e 78 6c 73 6d 2c 2a 2e 63 73 76 2c 2a 2e 78 6c 73 62 2c 2a 2e 6f 64 73 2c 2a 2e 73 78 63 2c 2a 2e 70 70 74 2c 2a 2e 70 70 74 78 2c 2a 2e 70 70 74 6d 2c 2a 2e 6f 64 70 2c 2a 2e 64 62 66 2c 2a 2e 6d 64 62 2c 2a 2e 41 43 43 44 41 2c 2a 2e 41 43 43 44 42 2c } //1 *.doc,*.docx,*.docm,*.odt,*.xls,*.xlsx,*.xlsm,*.csv,*.xlsb,*.ods,*.sxc,*.ppt,*.pptx,*.pptm,*.odp,*.dbf,*.mdb,*.ACCDA,*.ACCDB,
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_138{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 "
		
	strings :
		$a_01_0 = {56 42 2e 50 72 69 6e 74 65 72 } //1 VB.Printer
		$a_01_1 = {56 42 2e 53 68 61 70 65 } //1 VB.Shape
		$a_00_2 = {52 00 45 00 43 00 59 00 43 00 4c 00 45 00 52 00 } //1 RECYCLER
		$a_01_3 = {77 73 32 5f 33 32 2e 64 6c 6c 00 00 0e 00 00 00 67 65 74 68 6f 73 74 62 79 6e 61 6d 65 } //1
		$a_02_4 = {f5 6b 00 00 00 0b ?? ?? ?? ?? 31 ?? ?? f5 65 00 00 00 0b ?? ?? ?? ?? 31 ?? ?? f5 72 00 00 00 0b ?? ?? ?? ?? 31 ?? ?? f5 6e 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_02_4  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_rescan_139{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {50 c6 85 65 ff ff ff 63 c6 85 66 ff ff ff 20 c6 85 67 ff ff ff 6e c6 85 68 ff ff ff 65 c6 85 69 ff ff ff 74 c6 85 6a ff ff ff 20 c6 85 6b ff ff ff 73 c6 85 6c ff ff ff 74 c6 85 6d ff ff ff 6f c6 85 6e ff ff ff 70 c6 85 6f ff ff ff 20 c6 85 70 ff ff ff 4d c6 85 71 ff ff ff 70 c6 85 72 ff ff ff 73 c6 85 73 ff ff ff 53 c6 85 74 ff ff ff 76 c6 85 75 ff ff ff 63 88 9d 76 ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_140{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {c7 44 97 04 ff ff ff ff 6a 00 57 e8 ?? ?? ?? ?? 83 c4 08 33 c9 89 4d ?? 90 17 03 05 03 05 8b df 83 eb fc 8d 5f 04 8b df 8d 5b 04 8b 0f 3b 4d ?? 0f 8f } //1
		$a_01_1 = {41 75 74 6f 20 41 64 6a 75 73 74 20 63 6f 6d 70 6c 65 74 65 64 2e } //1 Auto Adjust completed.
		$a_03_2 = {c7 44 97 04 ff ff ff ff 6a 00 57 e8 ?? ?? ?? ?? 83 c4 08 33 c9 89 4d ?? 8d 5f 04 eb 14 8b 03 8b 50 14 52 6a 00 ff 50 18 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_141{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 06 00 00 "
		
	strings :
		$a_01_0 = {ac 8a c8 3c 0f 74 0f 66 81 7e ff cd 20 75 0a } //1
		$a_01_1 = {8a 02 88 45 ff 2c 61 42 3c 19 77 04 80 45 ff e0 } //1
		$a_01_2 = {6a 05 66 c7 01 58 68 89 71 02 66 c7 41 06 50 e9 } //1
		$a_01_3 = {c6 02 e9 8d 44 08 fb 89 42 01 83 eb 0c 89 5f 08 66 c7 07 58 68 89 77 02 66 c7 47 06 50 e9 } //1
		$a_01_4 = {ff 76 28 66 c7 45 fc 8b ff c7 45 f0 90 90 90 90 c6 45 f4 90 ff d7 } //1
		$a_01_5 = {8b 4e 24 8d 04 19 80 38 e8 75 08 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_rescan_142{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {67 6c 75 65 3a 4c 00 6e 6f 20 4c 75 61 20 70 72 6f 67 72 61 6d 20 66 6f 75 6e 64 20 69 6e 20 25 73 00 3d 00 61 72 67 00 74 6f 6f 20 6d 61 6e 79 20 61 72 67 75 6d 65 6e 74 73 20 74 6f 20 73 63 72 69 70 74 00 63 61 6e 6e 6f 74 20 6c 6f 63 61 74 65 20 74 68 69 73 20 65 78 65 63 75 74 61 62 6c 65 00 73 72 6c 75 61 00 6e 6f 74 20 65 6e 6f 75 67 68 20 6d 65 6d 6f 72 79 20 66 6f 72 20 73 74 61 74 65 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_143{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 06 00 00 "
		
	strings :
		$a_01_0 = {2f 00 72 00 6f 00 74 00 61 00 74 00 69 00 6f 00 6e 00 2e 00 69 00 6d 00 2e 00 70 00 68 00 70 00 } //1 /rotation.im.php
		$a_01_1 = {26 00 72 00 6f 00 74 00 69 00 64 00 3d 00 31 00 00 00 } //1
		$a_01_2 = {00 00 2f 00 6e 00 6f 00 74 00 69 00 66 00 69 00 00 00 } //1
		$a_01_3 = {00 00 2f 00 6e 00 6f 00 74 00 69 00 66 00 00 00 } //1
		$a_01_4 = {00 00 74 00 69 00 66 00 69 00 63 00 61 00 74 00 00 00 } //1
		$a_01_5 = {10 54 49 78 43 61 6d 70 61 69 67 6e 51 75 65 75 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_144{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {5a 32 56 75 59 57 74 68 61 79 42 52 59 32 78 6d 66 46 56 6b 62 30 52 31 63 77 68 5a 53 30 78 32 66 45 70 52 51 46 46 4b 56 56 74 31 63 79 34 64 61 32 35 30 63 6d 35 6c 61 52 77 56 61 47 76 51 41 58 4d 4d 64 6e 77 61 47 51 6b 45 46 51 49 50 44 67 38 52 42 61 35 68 63 32 35 77 63 6d 4a 76 59 31 5a 68 58 61 35 5a 61 32 35 34 65 6b 70 78 52 45 64 5a 53 34 35 52 51 30 35 41 51 6b 70 4a 64 47 61 75 6e 57 74 75 64 41 3d 3d } //1 Z2VuYWthayBRY2xmfFVkb0R1cwhZS0x2fEpRQFFKVVt1cy4da250cm5laRwVaGvQAXMMdnwaGQkEFQIPDg8RBa5hc25wcmJvY1ZhXa5Za254ekpxREdZS45RQ05AQkpJdGaunWtudA==
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_145{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 06 00 00 "
		
	strings :
		$a_80_0 = {7b 39 32 43 46 43 31 41 34 45 30 39 32 34 44 39 30 39 37 32 38 44 41 39 35 45 41 39 32 45 43 30 42 7d } //{92CFC1A4E0924D909728DA95EA92EC0B}  1
		$a_80_1 = {20 2d 69 6e 73 74 61 00 } // -insta  1
		$a_00_2 = {6d 00 73 00 69 00 64 00 6e 00 74 00 6c 00 64 00 33 00 32 00 } //1 msidntld32
		$a_00_3 = {6d 00 73 00 69 00 64 00 6e 00 74 00 6c 00 64 00 36 00 34 00 } //1 msidntld64
		$a_00_4 = {72 00 61 00 64 00 61 00 72 00 64 00 74 00 33 00 32 00 } //1 radardt32
		$a_00_5 = {72 00 61 00 64 00 61 00 72 00 64 00 74 00 36 00 34 00 } //1 radardt64
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_146{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_00_0 = {ff ff ff ff 04 00 00 00 65 78 69 74 00 } //1
		$a_00_1 = {ff ff ff ff 06 00 00 00 74 65 6c 6e 65 74 00 } //1
		$a_01_2 = {ff ff ff ff 05 00 00 00 0d 0a 2f 24 20 00 } //1
		$a_01_3 = {63 61 70 43 72 65 61 74 65 43 61 70 74 75 72 65 57 69 6e 64 6f 77 41 } //1 capCreateCaptureWindowA
		$a_01_4 = {61 63 6d 44 72 69 76 65 72 4f 70 65 6e } //1 acmDriverOpen
		$a_00_5 = {51 75 65 72 79 53 65 72 76 69 63 65 53 74 61 74 75 73 } //1 QueryServiceStatus
		$a_01_6 = {47 65 74 45 6e 68 4d 65 74 61 46 69 6c 65 48 65 61 64 65 72 } //1 GetEnhMetaFileHeader
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}
rule _#do_exhaustivehstr_rescan_147{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_01_0 = {74 63 72 79 70 74 5f 63 6c 32 5c 74 63 72 79 70 74 5f 63 6c 32 5c 52 65 6c 65 61 73 65 5c 73 5f 68 69 67 68 2e 70 64 62 } //1 tcrypt_cl2\tcrypt_cl2\Release\s_high.pdb
		$a_01_1 = {74 63 72 79 70 74 5f 63 6c 32 5c 74 63 72 79 70 74 5f 63 6c 32 5c 52 65 6c 65 61 73 65 5c 73 5f 6c 6f 77 2e 70 64 62 } //1 tcrypt_cl2\tcrypt_cl2\Release\s_low.pdb
		$a_01_2 = {5c 74 63 72 79 70 74 5c 52 65 6c 65 61 73 65 5c 73 5f 68 69 67 68 2e 70 64 62 } //1 \tcrypt\Release\s_high.pdb
		$a_01_3 = {5c 74 63 72 79 70 74 5c 52 65 6c 65 61 73 65 5c 73 5f 6c 6f 77 2e 70 64 62 } //1 \tcrypt\Release\s_low.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_148{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {38 00 32 00 36 00 33 00 30 00 34 00 31 00 31 00 65 00 35 00 64 00 66 00 30 00 65 00 30 00 63 00 00 00 00 00 4b 00 65 00 72 00 6e 00 00 00 00 00 65 00 6c 00 33 00 32 00 } //1
		$a_01_1 = {7b 00 35 00 35 00 46 00 31 00 35 00 34 00 43 00 30 00 2d 00 43 00 44 00 41 00 46 00 2d 00 34 00 35 00 43 00 34 00 2d 00 39 00 41 00 31 00 41 00 2d 00 00 00 38 00 35 00 32 00 46 00 46 00 35 00 31 00 46 00 39 00 35 00 31 00 45 00 00 00 00 00 7d 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_rescan_149{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,64 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {5f 43 6f 72 45 78 65 4d 61 69 6e } //10 _CorExeMain
		$a_01_1 = {54 00 68 00 69 00 73 00 20 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 20 00 69 00 73 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 20 00 74 00 6f 00 20 00 70 00 72 00 6f 00 76 00 69 00 64 00 65 00 20 00 63 00 6f 00 70 00 79 00 20 00 70 00 72 00 6f 00 74 00 65 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 } //1 This software is encrypted to provide copy protection.
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=11
 
}
rule _#do_exhaustivehstr_rescan_150{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_03_0 = {6a 0c 50 68 00 14 2d 00 90 09 03 00 8d 45 } //2
		$a_01_1 = {b8 4f 00 00 00 cd 41 66 3d 86 f3 0f 94 c0 0f b6 c0 } //2
		$a_01_2 = {b9 0a 00 00 00 b8 68 58 4d 56 66 ba 58 56 ed 81 fb 68 58 4d 56 0f 94 c0 0f b6 c0 } //1
		$a_01_3 = {33 c0 50 0f 01 4c 24 fe 58 c3 } //1
		$a_03_4 = {68 58 4d 56 c7 85 ?? ?? ff ff 58 56 00 00 } //1
		$a_03_5 = {b9 0a 00 00 00 8b 85 ?? ?? ff ff 66 8b 95 ?? ?? ff ff ed 3b 9d ?? ?? ff ff 0f 94 c0 0f b6 c0 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1) >=3
 
}
rule _#do_exhaustivehstr_rescan_151{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 00 63 00 65 00 73 00 73 00 6f 00 20 00 63 00 6f 00 72 00 72 00 65 00 74 00 61 00 6d 00 65 00 6e 00 74 00 65 00 } //1 Acesso corretamente
		$a_01_1 = {54 00 6f 00 6b 00 65 00 6e 00 20 00 63 00 6f 00 72 00 72 00 65 00 74 00 61 00 6d 00 65 00 6e 00 74 00 65 00 } //1 Token corretamente
		$a_01_2 = {53 00 65 00 6e 00 68 00 61 00 20 00 63 00 6f 00 72 00 72 00 65 00 74 00 61 00 6d 00 65 00 6e 00 74 00 65 00 } //1 Senha corretamente
		$a_01_3 = {42 61 72 72 61 54 69 6d 65 72 } //1 BarraTimer
		$a_01_4 = {4a 61 76 61 54 69 6d 65 72 } //1 JavaTimer
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_152{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {4d 00 53 00 41 00 46 00 44 00 20 00 54 00 63 00 70 00 69 00 70 00 20 00 5b 00 54 00 43 00 50 00 2f 00 49 00 50 00 5d 00 } //1 MSAFD Tcpip [TCP/IP]
		$a_01_1 = {57 53 43 49 6e 73 74 61 6c 6c 50 72 6f 76 69 64 65 72 } //1 WSCInstallProvider
		$a_01_2 = {57 53 43 45 6e 75 6d 50 72 6f 74 6f 63 6f 6c 73 } //1 WSCEnumProtocols
		$a_01_3 = {46 69 6e 64 52 65 73 6f 75 72 63 65 41 } //1 FindResourceA
		$a_01_4 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 } //1 LoadResource
		$a_01_5 = {57 72 69 74 65 46 69 6c 65 } //1 WriteFile
		$a_01_6 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 41 } //1 CreateProcessA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}
rule _#do_exhaustivehstr_rescan_153{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {66 33 45 d0 0f bf d0 52 ff 15 ?? ?? ?? ?? 8b d0 8d 4d c8 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 8b d0 8d 4d d4 ff 15 } //1
		$a_03_1 = {66 33 45 d0 0f bf c0 50 e8 ?? ?? ?? ?? 8b d0 8d 4d c8 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8b d0 8d 4d d4 e8 } //1
		$a_03_2 = {6b 70 ff fb 12 e7 0b ?? 00 04 00 23 44 ff 2a 31 74 ff 32 04 00 48 ff 44 ff 35 4c ff 00 0c 6b 70 ff f3 ff 00 c6 1c ?? ?? 00 07 f4 01 70 70 ff 1e ?? ?? 00 0b 6b 70 ff f4 01 a9 70 70 ff 00 0a 04 72 ff 64 6c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_154{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 05 00 00 "
		
	strings :
		$a_01_0 = {8b 78 04 0f b6 18 0f b7 ca 66 0f be 3c 0f 66 33 fb 66 33 fa bb ff 00 00 00 66 23 fb 42 66 89 3c 4e 66 3b 50 02 } //1
		$a_01_1 = {8b 50 04 0f b7 f1 8a 14 32 32 10 32 d1 41 88 14 3e 66 3b 48 02 } //1
		$a_03_2 = {50 68 22 a2 78 98 e8 ?? ?? ?? 00 8d 45 ?? 50 68 28 91 d0 03 53 6a 04 } //1
		$a_01_3 = {3c 61 7c 02 2c 20 c1 cf 0d 03 f8 e2 f0 81 ff 5b bc 4a 6a } //1
		$a_03_4 = {85 c0 74 39 8d 45 f4 50 8d 45 f8 50 8d 45 f0 50 ff 75 fc 89 5d f8 ff 15 ?? ?? ?? ?? 85 c0 74 14 ff 75 f4 ff 75 f8 ff 75 f0 57 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_155{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 08 00 00 "
		
	strings :
		$a_01_0 = {00 42 46 44 44 4f 53 2f 25 64 2d 25 64 00 } //1 䈀䑆佄⽓搥┭d
		$a_01_1 = {00 46 59 48 48 4f 53 3d 25 64 2b 25 64 28 4d 42 29 00 } //1 䘀䡙佈㵓搥┫⡤䉍)
		$a_01_2 = {00 46 59 59 4c 43 53 3d 25 64 2b 25 64 28 4d 42 29 } //1
		$a_01_3 = {00 41 63 63 65 70 74 2d 4c 61 6e 67 75 61 67 65 3a 20 7a 68 2d 63 6e 0d 0a } //1
		$a_01_4 = {00 53 54 4f 50 41 54 54 41 43 4b 00 } //1 匀佔䅐呔䍁K
		$a_01_5 = {00 52 45 54 55 52 4e 50 4f 57 45 52 } //1 刀呅剕偎坏剅
		$a_01_6 = {79 6f 75 20 77 69 6c 6c 20 63 61 6e 27 74 20 72 65 67 69 73 74 20 70 72 6f 67 72 61 6d 00 } //2 潹⁵楷汬挠湡琧爠来獩⁴牰杯慲m
		$a_01_7 = {b1 72 b0 65 88 4c 24 02 88 4c 24 06 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2) >=2
 
}
rule _#do_exhaustivehstr_rescan_156{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 06 00 00 "
		
	strings :
		$a_01_0 = {2e 3f 41 56 62 70 72 6f 74 65 63 74 6f 72 40 40 00 } //1
		$a_01_1 = {62 00 50 00 72 00 6f 00 74 00 65 00 63 00 74 00 6f 00 72 00 46 00 6f 00 72 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 00 00 } //1
		$a_01_2 = {2e 3f 41 56 69 6e 6a 65 63 74 6f 72 40 70 72 6f 74 65 63 74 69 6f 6e 40 40 00 } //1 㼮噁湩敪瑣牯灀潲整瑣潩䁮@
		$a_01_3 = {2e 3f 41 56 69 74 65 6d 5f 73 65 74 74 69 6e 67 73 40 70 72 6f 74 65 63 74 69 6f 6e 40 40 00 } //1
		$a_01_4 = {5c 62 70 72 6f 74 65 63 74 2e 70 64 62 00 } //1
		$a_01_5 = {2e 3f 41 56 50 72 6f 74 65 63 74 6f 72 53 65 72 76 69 63 65 40 40 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_157{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {54 53 55 20 4c 6f 61 64 65 72 00 } //1
		$a_01_1 = {4e 6f 20 69 6e 73 74 61 6c 6c 65 72 20 61 76 61 69 6c 61 62 6c 65 20 66 6f 72 20 74 68 69 73 20 57 69 6e 64 6f 77 73 20 76 65 72 73 69 6f 6e } //1 No installer available for this Windows version
		$a_01_2 = {57 00 65 00 62 00 43 00 61 00 6b 00 65 00 20 00 4c 00 4c 00 43 00 2e 00 20 00 20 00 41 00 6c 00 6c 00 20 00 72 00 69 00 67 00 68 00 74 00 73 00 20 00 72 00 65 00 73 00 65 00 72 00 76 00 65 00 64 00 2e 00 } //2 WebCake LLC.  All rights reserved.
		$a_01_3 = {61 00 70 00 69 00 2e 00 67 00 65 00 74 00 77 00 65 00 62 00 63 00 61 00 6b 00 65 00 2e 00 63 00 6f 00 6d 00 } //2 api.getwebcake.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=2
 
}
rule _#do_exhaustivehstr_rescan_158{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_03_0 = {0f b7 41 14 03 f8 0f b7 49 06 60 8b 47 14 85 c0 74 ?? 8b 47 08 85 c0 74 } //1
		$a_01_1 = {46 61 73 74 4d 4d 20 42 6f 72 6c 61 6e 64 20 45 64 69 74 69 6f 6e 20 28 63 29 20 32 30 30 34 20 2d 20 32 30 30 38 20 50 69 65 72 72 65 20 6c 65 20 52 69 63 68 65 20 2f 20 50 72 6f 66 65 73 73 69 6f 6e 61 6c 20 53 6f 66 74 77 61 72 65 20 44 65 76 65 6c 6f 70 6d 65 6e 74 } //1 FastMM Borland Edition (c) 2004 - 2008 Pierre le Riche / Professional Software Development
		$a_01_2 = {53 79 73 74 65 6d 3a 3a 44 65 6c 70 68 69 49 6e 74 65 72 66 61 63 65 3c 49 44 69 73 70 61 74 63 68 3e 00 } //1
		$a_01_3 = {00 7a 78 63 7a 63 7a 78 63 00 } //1 稀捸捺硺c
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_159{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {50 73 53 65 74 43 72 65 61 74 65 50 72 6f 63 65 73 73 4e 6f 74 69 66 79 52 6f 75 74 69 6e 65 } //1 PsSetCreateProcessNotifyRoutine
		$a_01_1 = {5a 77 51 75 65 72 79 53 79 73 74 65 6d 49 6e 66 6f 72 6d 61 74 69 6f 6e } //1 ZwQuerySystemInformation
		$a_01_2 = {6e 74 6f 73 6b 72 6e 6c 2e 65 78 65 } //1 ntoskrnl.exe
		$a_01_3 = {50 73 4c 6f 6f 6b 75 70 50 72 6f 63 65 73 73 42 79 50 72 6f 63 65 73 73 49 64 } //1 PsLookupProcessByProcessId
		$a_01_4 = {4d 6d 49 73 41 64 64 72 65 73 73 56 61 6c 69 64 } //1 MmIsAddressValid
		$a_01_5 = {4b 65 44 65 6c 61 79 45 78 65 63 75 74 69 6f 6e 54 68 72 65 61 64 } //1 KeDelayExecutionThread
		$a_01_6 = {50 73 43 72 65 61 74 65 53 79 73 74 65 6d 54 68 72 65 61 64 } //1 PsCreateSystemThread
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}
rule _#do_exhaustivehstr_rescan_160{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {e3 40 fe 45 fd 0f b6 45 fd 0f b6 14 38 88 55 ff 00 55 fc 0f b6 45 fc 8a 14 38 88 55 fe 0f b6 45 fd 88 14 38 0f b6 45 fc 8a 55 ff 88 14 38 8a 55 ff 02 55 fe 8a 14 3a 8b 45 f8 30 14 30 ff 45 f8 e2 c0 8a 45 fd 88 03 8a 45 fc 88 43 01 } //1
		$a_03_1 = {3d c9 00 00 00 75 0f 68 a7 a7 a7 00 ff 75 10 e8 ?? ?? 00 00 eb ?? 3d ca 00 00 00 75 ?? 6a 00 ff 75 10 e8 } //1
		$a_01_2 = {d7 84 c0 78 f7 8a e0 c0 e8 04 c0 e4 04 0b d0 49 78 28 ac d7 84 c0 78 f7 8a e0 c0 e8 02 c0 e4 06 c1 e0 08 0b d0 49 78 12 ac d7 84 c0 78 f7 c1 e0 10 0b d0 89 17 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_rescan_161{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 0b 00 00 "
		
	strings :
		$a_02_0 = {46 69 6c 65 4d 65 6d 2e 64 6c 6c 00 [0-03] 64 65 66 61 75 6c 74 [0-0a] 2e 64 61 74 } //4
		$a_00_1 = {00 4c 6f 63 6b 2e 64 6c 6c } //4
		$a_00_2 = {4e 6f 50 72 6f 74 65 63 74 65 64 4d 6f 64 65 42 61 6e 6e 65 72 } //4 NoProtectedModeBanner
		$a_00_3 = {63 74 66 6d 6f 6e 2e } //2 ctfmon.
		$a_00_4 = {2e 6c 6e 6b 00 } //2
		$a_00_5 = {44 4c 4c 4d 4f 44 55 4c 45 } //4 DLLMODULE
		$a_00_6 = {46 49 52 45 46 4f 58 2e 45 58 45 } //1 FIREFOX.EXE
		$a_00_7 = {43 48 52 4f 4d 45 2e 45 58 45 } //1 CHROME.EXE
		$a_00_8 = {49 45 53 54 41 52 54 } //1 IESTART
		$a_01_9 = {64 ff 30 64 89 20 83 eb 01 72 07 74 0e 4b 74 22 eb 43 55 e8 } //10
		$a_01_10 = {74 44 c7 04 24 28 01 00 00 8b d4 8b c3 e8 } //10
	condition:
		((#a_02_0  & 1)*4+(#a_00_1  & 1)*4+(#a_00_2  & 1)*4+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2+(#a_00_5  & 1)*4+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_01_9  & 1)*10+(#a_01_10  & 1)*10) >=21
 
}
rule _#do_exhaustivehstr_rescan_162{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 00 61 00 64 00 73 00 70 00 6f 00 73 00 74 00 62 00 61 00 63 00 6b 00 5f 00 73 00 65 00 72 00 76 00 65 00 72 00 2e 00 61 00 73 00 70 00 78 00 3f 00 75 00 73 00 65 00 72 00 69 00 64 00 3d 00 25 00 73 00 26 00 73 00 6f 00 75 00 72 00 63 00 65 00 3d 00 25 00 73 00 } //1 /adspostback_server.aspx?userid=%s&source=%s
		$a_01_1 = {2f 00 77 00 73 00 2f 00 72 00 65 00 70 00 6f 00 72 00 74 00 77 00 73 00 2e 00 61 00 73 00 6d 00 78 00 3f 00 77 00 73 00 64 00 6c 00 } //1 /ws/reportws.asmx?wsdl
		$a_01_2 = {2f 00 61 00 70 00 69 00 5f 00 61 00 6a 00 61 00 78 00 2e 00 61 00 73 00 68 00 78 00 3f 00 63 00 6c 00 69 00 65 00 6e 00 74 00 69 00 64 00 3d 00 25 00 73 00 } //1 /api_ajax.ashx?clientid=%s
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_163{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {43 6f 6e 66 69 67 75 72 61 65 73 64 65 42 6c 6f 71 75 65 61 64 6f 72 64 65 50 6f 70 75 70 73 32 } //1 ConfiguraesdeBloqueadordePopups2
		$a_01_1 = {4f 70 65 73 64 61 49 6e 74 65 72 6e 65 74 31 43 6c 69 63 6b } //1 OpesdaInternet1Click
		$a_01_2 = {53 6f 62 72 65 6f 49 6e 74 65 72 6e 65 74 45 78 70 6c 6f 72 65 72 32 } //1 SobreoInternetExplorer2
		$a_01_3 = {45 6d 61 69 6c 73 65 6e 6f 74 63 69 61 73 32 } //1 Emailsenotcias2
		$a_01_4 = {43 68 61 6d 61 64 61 6e 61 49 6e 74 65 72 6e 65 74 32 } //1 ChamadanaInternet2
		$a_01_5 = {42 61 72 72 61 64 6f 45 78 70 6c 6f 72 65 72 32 } //1 BarradoExplorer2
		$a_01_6 = {57 69 6e 64 6f 77 73 75 70 64 61 74 65 32 } //1 Windowsupdate2
		$a_01_7 = {57 69 6e 64 6f 77 73 6d 65 73 73 65 6e 67 65 72 32 } //1 Windowsmessenger2
		$a_01_8 = {47 6f 6f 67 6c 65 32 } //1 Google2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}
rule _#do_exhaustivehstr_rescan_164{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 0a 00 00 "
		
	strings :
		$a_03_0 = {ff 37 81 c3 54 32 77 00 5b 58 85 db 0f 85 ?? ?? ?? ?? e9 } //1
		$a_01_1 = {ff 37 4e 4e 81 eb 53 32 87 00 5b 58 85 db 0f 85 } //1
		$a_03_2 = {68 6f 6e 5c (4f|50) ?? 74 69 66 79 5c } //1
		$a_01_3 = {5c 65 69 6f 6c 6f 68 6f 6e 20 20 6f 74 69 66 79 5c } //1 \eiolohon  otify\
		$a_03_4 = {72 6f 6c 78 65 74 30 30 31 5c ?? 65 72 76 69 63 65 73 5c 58 68 61 72 ?? ?? ?? 63 63 65 73 73 5c } //1
		$a_03_5 = {2e 6e 65 74 00 90 0a 10 00 00 78 31 2e } //1
		$a_01_6 = {00 6e 61 63 6c 65 64 3a 00 } //1
		$a_03_7 = {6e 73 31 2e [0-10] 2e (6d 65 2e 75 6b|6e 65 74) } //1
		$a_03_8 = {6e 73 31 2e [0-10] 2e 63 6f (6d|2e) } //1
		$a_03_9 = {6e 73 31 2e [0-10] 2e 78 79 7a } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1+(#a_01_6  & 1)*1+(#a_03_7  & 1)*1+(#a_03_8  & 1)*1+(#a_03_9  & 1)*1) >=3
 
}
rule _#do_exhaustivehstr_rescan_165{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 00 6f 00 6d 00 2e 00 65 00 6d 00 62 00 61 00 72 00 63 00 61 00 64 00 65 00 72 00 6f 00 2e 00 41 00 55 00 54 00 4f 00 52 00 55 00 4e 00 } //1 com.embarcadero.AUTORUN
		$a_01_1 = {54 68 65 20 49 44 20 62 65 6c 6f 77 20 69 6e 64 69 63 61 74 65 73 20 61 70 70 20 73 75 70 70 6f 72 74 20 66 6f 72 20 57 69 6e 64 6f 77 73 20 56 69 73 74 61 } //1 The ID below indicates app support for Windows Vista
		$a_01_2 = {54 68 65 20 49 44 20 62 65 6c 6f 77 20 69 6e 64 69 63 61 74 65 73 20 61 70 70 20 73 75 70 70 6f 72 74 20 66 6f 72 20 57 69 6e 64 6f 77 73 20 31 30 } //1 The ID below indicates app support for Windows 10
		$a_01_3 = {45 6d 62 61 72 63 61 64 65 72 6f 20 44 65 6c 70 68 69 20 66 6f 72 20 57 69 6e 33 32 20 63 6f 6d 70 69 6c 65 72 20 76 65 72 73 69 6f 6e 20 33 35 2e 30 } //1 Embarcadero Delphi for Win32 compiler version 35.0
		$a_01_4 = {4f 66 66 69 63 65 20 32 30 32 34 } //1 Office 2024
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule _#do_exhaustivehstr_rescan_166{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {63 00 61 00 63 00 6c 00 73 00 2e 00 65 00 78 00 65 00 20 00 [0-40] 20 00 2f 00 74 00 20 00 2f 00 65 00 20 00 2f 00 63 00 20 00 2f 00 67 00 20 00 75 00 73 00 65 00 72 00 73 00 3a 00 66 00 } //1
		$a_01_1 = {4d 61 69 6c 42 65 65 2e 53 6d 74 70 4d 61 69 6c 00 } //1
		$a_81_2 = {40 61 6c 69 63 65 2e 69 74 3b 40 61 6f 6c 2e 63 6f 6d 3b 40 61 74 74 2e 6e 65 74 3b 40 62 61 64 6f 6f 2e 63 6f 6d 3b 40 62 65 6c 6c 73 6f 75 74 68 2e 6e 65 74 3b } //1 @alice.it;@aol.com;@att.net;@badoo.com;@bellsouth.net;
		$a_01_3 = {2f 00 6f 00 75 00 74 00 6c 00 6f 00 6f 00 6b 00 39 00 2f 00 73 00 70 00 65 00 63 00 73 00 2f 00 77 00 65 00 6c 00 63 00 6f 00 6d 00 65 00 6d 00 73 00 67 00 2f 00 } //1 /outlook9/specs/welcomemsg/
		$a_01_4 = {61 2e 61 2e 61 37 2e 72 65 73 6f 75 72 63 65 73 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule _#do_exhaustivehstr_rescan_167{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 0c 00 00 "
		
	strings :
		$a_01_0 = {4a 6f 67 61 4d 61 63 72 6f 49 45 } //1 JogaMacroIE
		$a_01_1 = {4a 6f 67 61 4d 61 63 72 6f 43 68 72 6f 6d 65 } //1 JogaMacroChrome
		$a_01_2 = {4a 6f 67 61 53 74 61 6e 64 61 72 64 49 45 } //1 JogaStandardIE
		$a_01_3 = {4a 6f 67 61 53 74 61 6e 64 61 72 64 43 68 72 6f 6d 65 } //1 JogaStandardChrome
		$a_01_4 = {4a 6f 67 61 53 75 70 65 72 76 69 65 6c 6c 65 49 45 } //1 JogaSupervielleIE
		$a_01_5 = {4a 6f 67 61 53 75 70 65 72 76 69 65 6c 6c 65 43 68 72 6f 6d 65 } //1 JogaSupervielleChrome
		$a_01_6 = {4a 6f 67 61 47 61 6c 69 63 69 61 49 45 } //1 JogaGaliciaIE
		$a_01_7 = {4a 6f 67 61 47 61 6c 69 63 69 61 43 68 72 6f 6d 65 } //1 JogaGaliciaChrome
		$a_01_8 = {4a 6f 67 61 43 72 65 64 69 63 6f 6f 70 49 45 } //1 JogaCredicoopIE
		$a_01_9 = {4a 6f 67 61 43 72 65 64 69 63 6f 6f 70 43 68 72 6f 6d 65 } //1 JogaCredicoopChrome
		$a_01_10 = {4a 6f 67 61 42 42 56 41 43 68 72 6f 6d 65 } //1 JogaBBVAChrome
		$a_01_11 = {4a 6f 67 61 42 42 56 41 49 45 } //1 JogaBBVAIE
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_rescan_168{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 06 00 00 "
		
	strings :
		$a_01_0 = {c1 e9 08 32 d1 88 54 28 ff 8b 06 0f b6 44 28 ff 66 03 f8 66 69 c7 6d ce 66 05 bf 58 8b f8 43 66 ff 0c 24 75 } //2
		$a_03_1 = {66 05 bf 58 90 09 0b 00 [0-06] 66 69 ?? 6d ce } //2
		$a_00_2 = {4d 79 5f 4d 5f 69 5f 6e 69 54 5f 43 5f 50 43 5f 6c 69 65 6e 74 } //2 My_M_i_niT_C_PC_lient
		$a_01_3 = {56 62 42 45 36 6c 35 4f 55 6a 55 4c 45 33 52 4b 43 71 45 55 50 70 67 6f 64 35 48 79 39 63 36 71 68 4e 35 6e 58 75 34 66 43 52 38 65 38 72 49 72 4f 6e 49 6a 62 5a 34 58 7a 33 5a 36 4a 66 71 52 79 64 6e 42 6d 32 43 48 2b 44 62 57 7a 36 48 00 ff ff ff ff 12 00 00 00 57 61 72 6e 4f 6e 5a 6f 6e 65 43 72 6f 73 73 69 6e 67 00 00 ff ff ff ff 12 00 00 00 57 61 72 6e 4f 6e 50 6f 73 74 52 65 64 69 72 65 63 74 00 00 } //2
		$a_00_4 = {6e 65 74 73 74 61 74 20 2d 61 20 2d 6e 20 2d 70 20 74 63 70 20 7c 20 66 69 6e 64 73 74 72 20 6c 69 73 74 65 6e 69 6e 67 00 } //1
		$a_00_5 = {73 65 78 6d 65 3a } //1 sexme:
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_00_2  & 1)*2+(#a_01_3  & 1)*2+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_rescan_169{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_03_0 = {50 6f 6c 69 63 69 65 73 20 7b 90 05 01 01 0d 0a 09 09 09 09 09 09 4e 6f 52 65 6d 6f 76 65 20 45 78 74 20 7b 90 05 01 01 0d 0a 09 09 09 09 09 09 09 4e 6f 52 65 6d 6f 76 65 20 43 4c 53 49 44 20 7b 90 05 01 01 0d 0a 09 09 09 09 09 09 09 09 76 61 6c 20 27 25 50 4c 55 47 49 4e 5f 43 4c 53 49 44 25 27 20 3d 20 73 20 27 31 27 } //1
		$a_01_1 = {5b 00 25 00 70 00 3a 00 25 00 70 00 5d 00 20 00 45 00 20 00 74 00 69 00 6d 00 65 00 6f 00 75 00 74 00 20 00 69 00 6e 00 6a 00 65 00 63 00 74 00 20 00 25 00 64 00 } //1 [%p:%p] E timeout inject %d
		$a_01_2 = {6d 00 69 00 6e 00 69 00 3a 00 3a 00 69 00 6e 00 69 00 5f 00 73 00 65 00 63 00 74 00 69 00 6f 00 6e 00 3a 00 3a 00 67 00 65 00 74 00 3a 00 20 00 69 00 6e 00 64 00 65 00 78 00 20 00 25 00 64 00 20 00 6f 00 66 00 20 00 30 00 2e 00 2e 00 25 00 64 00 } //1 mini::ini_section::get: index %d of 0..%d
		$a_01_3 = {5b 00 25 00 70 00 3a 00 25 00 70 00 5d 00 20 00 45 00 3a 00 25 00 64 00 20 00 6d 00 6f 00 64 00 69 00 66 00 79 00 20 00 6e 00 61 00 76 00 69 00 67 00 61 00 74 00 69 00 6f 00 6e 00 } //1 [%p:%p] E:%d modify navigation
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_170{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 06 00 00 "
		
	strings :
		$a_01_0 = {41 49 43 34 00 00 00 00 41 49 43 35 00 00 00 00 41 49 43 36 00 00 00 00 ff ff ff ff 10 00 00 00 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 00 00 00 00 41 49 43 37 00 00 00 00 41 49 43 38 00 00 00 00 41 49 43 39 00 00 00 00 41 49 43 39 2e 6c 6f 6f 70 00 } //1
		$a_01_1 = {62 00 00 00 ff ff ff ff 01 00 00 00 69 00 00 00 ff ff ff ff 01 00 00 00 6e 00 00 00 ff ff ff ff 01 00 00 00 2e 00 00 00 ff ff ff ff 01 00 00 00 64 00 00 00 ff ff ff ff 01 00 00 00 61 00 00 00 ff ff ff ff 01 00 00 00 74 00 } //1
		$a_01_2 = {25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 00 00 00 00 ff ff ff ff 0e 00 00 00 25 73 25 73 25 73 25 73 25 73 25 73 25 73 00 00 55 } //1
		$a_01_3 = {25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 00 00 00 00 ff ff ff ff 0a 00 00 00 25 73 25 73 25 73 25 73 25 73 00 00 55 } //1
		$a_03_4 = {8b 45 f4 83 78 04 00 0f 86 ?? ?? ?? ?? 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 90 09 0f 00 64 89 10 eb 0a e9 ?? ?? ?? ?? e8 } //1
		$a_03_5 = {6a 04 68 00 30 00 00 8b 45 fc 50 6a 00 ff 15 ?? ?? ?? ?? 89 45 f8 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 90 09 0f 00 64 89 10 eb 0a e9 ?? ?? ?? ?? e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_171{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 0a 00 00 "
		
	strings :
		$a_01_0 = {44 00 65 00 65 00 70 00 20 00 53 00 63 00 61 00 6e 00 00 00 43 00 75 00 73 00 74 00 6f 00 6d 00 20 00 53 00 63 00 61 00 6e 00 00 00 } //1
		$a_01_1 = {2e 3f 41 56 5a 53 63 61 6e 46 72 61 6d 65 40 40 00 } //1
		$a_01_2 = {2e 3f 41 56 5a 53 63 61 6e 52 65 73 75 6c 74 40 40 00 } //1 㼮噁博慣剮獥汵䁴@
		$a_01_3 = {50 00 6c 00 65 00 61 00 73 00 65 00 20 00 63 00 6c 00 69 00 63 00 6b 00 20 00 22 00 41 00 75 00 74 00 6f 00 20 00 41 00 64 00 6a 00 75 00 73 00 74 00 22 00 20 00 62 00 75 00 74 00 74 00 6f 00 6e 00 20 00 74 00 6f 00 20 00 65 00 72 00 61 00 73 00 65 00 20 00 61 00 6c 00 6c 00 20 00 69 00 6e 00 66 00 65 00 63 00 74 00 65 00 64 00 20 00 66 00 69 00 6c 00 65 00 } //1 Please click "Auto Adjust" button to erase all infected file
		$a_01_4 = {47 00 75 00 61 00 72 00 64 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 00 00 } //1
		$a_01_5 = {71 00 77 00 65 00 61 00 73 00 64 00 66 00 67 00 68 00 00 00 } //1
		$a_81_6 = {5c 70 72 6f 74 65 63 74 25 73 2e 65 78 65 00 } //1
		$a_81_7 = {6e 67 6c 69 63 68 6b 65 69 74 2d 4d 61 6e 61 67 65 72 00 } //1
		$a_01_8 = {50 00 6c 00 65 00 61 00 73 00 65 00 20 00 62 00 65 00 20 00 63 00 61 00 72 00 65 00 66 00 75 00 6c 00 20 00 77 00 68 00 69 00 6c 00 65 00 20 00 61 00 64 00 6a 00 75 00 73 00 74 00 69 00 6e 00 67 00 20 00 74 00 68 00 65 00 20 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 2e 00 00 00 } //1
		$a_01_9 = {50 6a 18 6a 50 6a 16 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_172{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 09 00 00 "
		
	strings :
		$a_01_0 = {5c 67 67 67 5c 62 75 69 6c 64 5c 52 65 6c 65 61 73 65 5f 33 32 5c 6c 69 62 67 6c 69 62 2d 32 2e 30 2d 30 2e 70 64 62 } //1 \ggg\build\Release_32\libglib-2.0-0.pdb
		$a_01_1 = {6e 45 6c 64 56 42 58 62 36 57 49 38 68 68 58 68 4c 4a 45 67 4a 31 4d 33 } //1 nEldVBXb6WI8hhXhLJEgJ1M3
		$a_01_2 = {8b 45 d4 30 45 e0 30 65 e1 30 45 e2 30 65 e3 30 45 e4 30 65 e5 30 45 e6 30 65 e7 8d 45 e0 50 e8 } //1
		$a_03_3 = {8b c2 8a ca c1 e8 03 80 e1 07 8a 04 30 d2 f8 24 01 88 82 ?? ?? ?? ?? 42 83 fa 40 7c e3 } //1
		$a_03_4 = {51 6a 00 6a 00 6a 14 8d 8d ?? ?? ?? ?? 51 ff b5 ?? ?? ?? ?? ff d0 85 c0 0f 84 ?? ?? ?? ?? b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 51 } //1
		$a_03_5 = {30 45 d8 30 65 d9 30 45 da 30 65 db 30 45 dc 30 65 dd 30 45 de 30 65 df 8d 45 d8 50 e8 90 09 03 00 8b 45 } //1
		$a_03_6 = {68 06 02 00 00 50 66 89 84 24 ?? ?? 00 00 8d 84 24 ?? ?? 00 00 50 e8 ?? ?? ?? ?? 83 c4 0c b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? b9 ?? ?? ?? ?? 8b f8 e8 ?? ?? ?? ?? b9 ?? ?? ?? ?? 8b f0 e8 ?? ?? ?? ?? 8d 8c 24 ?? ?? 00 00 51 68 04 01 00 00 8d 8c 24 ?? ?? 00 00 51 57 56 50 ff 15 } //1
		$a_03_7 = {51 6a 00 6a 00 6a 14 8d 8d ?? ?? ?? ?? 51 ff b5 ?? ?? ?? ?? ff d0 85 c0 0f 84 ?? ?? ?? ?? [0-20] b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? b9 ?? ?? ?? ?? 8b f0 e8 ?? ?? ?? ?? 50 56 } //1
		$a_03_8 = {50 6a 00 6a 00 6a 14 8d 85 ?? ?? ?? ?? c7 85 ?? ?? ?? ?? 01 66 00 00 50 ff b5 ?? ?? ?? ?? 66 c7 ?? ?? ?? ?? ff 08 02 c7 85 ?? ?? ?? ?? 08 00 00 00 ff 15 ?? ?? ?? ?? 85 c0 0f 84 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1+(#a_03_6  & 1)*1+(#a_03_7  & 1)*1+(#a_03_8  & 1)*2) >=1
 
}
rule _#do_exhaustivehstr_rescan_173{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 31 00 00 "
		
	strings :
		$a_03_0 = {fb c7 44 24 ?? ff ff ff ff c7 44 24 90 09 07 00 c7 44 24 ?? ?? 2a } //1
		$a_03_1 = {83 d1 ff bf ?? ?? ?? ?? 33 c7 89 44 24 20 [0-04] 89 4c 24 24 c7 44 24 18 ?? ?? ?? ?? c7 44 24 1c ff ff ff ff c7 44 24 0c } //1
		$a_01_2 = {8b 04 81 ff 75 0c 03 45 08 ff d0 } //1
		$a_03_3 = {8b 4c 24 20 8b 54 24 24 bf ?? ?? ?? ?? 33 cf be ?? ?? ?? ?? 03 ce 89 4c 24 14 } //1
		$a_03_4 = {8b 44 24 20 8b 4c 24 24 bb ?? ?? ?? ?? 33 c3 05 ?? ?? ?? ?? 89 44 24 (10|20) } //1
		$a_03_5 = {83 d7 ff 33 f3 83 f7 00 8b c6 05 ?? ?? ?? ?? 8b cf 81 d1 90 09 06 00 81 c6 } //1
		$a_03_6 = {8b 44 24 28 8b 4c 24 2c be ?? ?? ?? ?? 33 c6 05 ?? ?? ?? ?? 89 44 24 20 } //1
		$a_03_7 = {8b 45 08 a3 ?? ?? ?? ?? 8b 45 0c a3 ?? ?? ?? ?? 8d 45 04 89 44 24 ?? 8b 44 24 ?? 8b 4c 24 ?? be ?? ?? ?? ?? 33 c6 05 } //1
		$a_03_8 = {8b 44 24 18 8b 4c 24 1c 35 ?? ?? ?? ?? 05 ?? ?? ?? ?? 89 44 24 0c } //1
		$a_03_9 = {b3 9c 57 05 ?? 18 ce 54 } //1
		$a_03_10 = {8b 44 24 18 8b 4c 24 1c 56 57 35 ?? ?? ?? ?? 05 } //1
		$a_01_11 = {c7 44 24 68 be 0f 00 00 c7 44 24 78 3e 00 00 00 } //1
		$a_01_12 = {c1 e8 09 8b 45 9c 8b 4d a4 } //1
		$a_03_13 = {c7 44 24 14 ff ff ff ff c7 44 24 (08|18) ?? 90 17 03 02 02 02 bb f8 2b fe 05 ff ff c7 44 24 90 03 01 01 0c 1c ff ff ff ff } //1
		$a_03_14 = {0b c2 2b c1 35 ?? ?? ?? ?? 8b 00 } //1
		$a_03_15 = {0a d0 80 f2 ?? 3a ca 0f 85 } //1
		$a_03_16 = {8b 44 24 20 8b 4c 24 24 35 ?? ?? ?? ?? 05 } //1
		$a_03_17 = {ff ff ff ff c7 44 24 (1c|20) ?? ?? ?? ff c7 44 24 (|) 20 24 ff ff ff ff 90 09 13 00 c7 44 24 (|) 20 24 } //1
		$a_03_18 = {c7 45 fc ff ff ff ff c7 45 f8 ?? ?? ?? ff c7 45 fc ff ff ff ff } //1
		$a_01_19 = {0f 84 1e 00 00 00 8b 45 f0 8b 75 f4 33 c2 03 c1 } //1
		$a_01_20 = {39 02 8b 45 fc 0f 86 36 00 00 00 29 08 e9 31 00 00 00 80 38 00 8b 45 fc 0f 84 23 00 00 00 } //1
		$a_01_21 = {ff d0 89 44 24 18 47 81 ff 00 10 00 00 0f 82 d8 ff ff ff } //1
		$a_03_22 = {d6 22 00 00 c7 45 fc 00 00 00 00 81 35 ?? ?? ?? ?? 82 1f 00 00 8b 45 fc 81 1d ?? ?? ?? ?? a2 68 00 00 } //1
		$a_01_23 = {48 75 73 73 2e 63 6f 6d 00 3f 54 68 72 65 61 64 41 40 40 59 47 58 4b 40 5a } //1
		$a_03_24 = {66 03 c2 66 8b 55 ?? 66 33 c1 66 3b d0 0f 82 } //1
		$a_03_25 = {02 d0 8a c2 2a c1 (04|2c) ?? 00 45 } //1
		$a_03_26 = {5f 5b 3b c1 0f 85 17 00 00 00 3b f2 0f 85 0f 00 00 00 a1 ?? ?? ?? ?? 8b 4d 10 89 01 e9 16 00 00 00 } //1
		$a_03_27 = {2a ca 32 c1 8a 4c 24 ?? 34 ?? 3a c8 } //1
		$a_03_28 = {8b 5d 08 02 45 0c 2a c2 8b 55 ?? 2c ?? 88 04 1a } //1
		$a_03_29 = {d2 e2 0f b6 4c 24 ?? f6 ea 3a c8 } //1
		$a_03_30 = {66 8b 4c 24 10 66 c1 e0 ?? 66 2b c6 66 3b c8 } //1
		$a_03_31 = {d2 e2 8a 4c 24 ?? 22 c2 34 ?? 3a c8 } //1
		$a_03_32 = {d2 e0 8a 4c 24 ?? ?? ?? 04 ?? 3a c8 } //1
		$a_03_33 = {0f b7 c0 99 f7 f9 66 8b 44 24 ?? 33 d7 66 3b c2 } //1
		$a_03_34 = {32 c1 8a 4c 24 ?? 2c ?? 3a c8 } //1
		$a_03_35 = {f6 e9 8a 4c 24 ?? 2c ?? 3a c8 } //1
		$a_03_36 = {99 f7 f9 8a 44 24 ?? 80 f2 4b 3a c2 } //1
		$a_03_37 = {8a 4c 24 10 0c ?? 04 ?? 3a } //1
		$a_03_38 = {66 0b c2 66 8b 54 24 ?? 66 33 c1 66 3b d0 } //1
		$a_03_39 = {02 c1 8a 4c 24 ?? 04 ?? 3a c8 } //1
		$a_03_40 = {99 f7 fb 0f b7 54 24 ?? 0f b7 c0 03 d0 } //1
		$a_03_41 = {02 d0 8a c2 2a c1 2c ?? 00 45 ff } //1
		$a_03_42 = {f7 f9 8a 4c 24 ?? [0-03] 34 ?? 3a c8 } //1
		$a_01_43 = {66 23 c2 66 2b c6 66 3b c8 } //1
		$a_01_44 = {66 2b c7 66 33 c6 66 3b c8 } //1
		$a_03_45 = {33 d0 89 54 24 ?? 8b 54 24 ?? 2b d1 33 d0 } //1
		$a_03_46 = {8a 4c 24 13 f6 ea 34 ?? 3a c8 } //1
		$a_03_47 = {33 c8 88 4c 24 ?? 8b 44 24 ?? 33 c6 03 c3 } //1
		$a_03_48 = {8a 55 ff 24 ?? 2c ?? 3a d0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1+(#a_03_6  & 1)*1+(#a_03_7  & 1)*1+(#a_03_8  & 1)*1+(#a_03_9  & 1)*1+(#a_03_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_03_13  & 1)*1+(#a_03_14  & 1)*1+(#a_03_15  & 1)*1+(#a_03_16  & 1)*1+(#a_03_17  & 1)*1+(#a_03_18  & 1)*1+(#a_01_19  & 1)*1+(#a_01_20  & 1)*1+(#a_01_21  & 1)*1+(#a_03_22  & 1)*1+(#a_01_23  & 1)*1+(#a_03_24  & 1)*1+(#a_03_25  & 1)*1+(#a_03_26  & 1)*1+(#a_03_27  & 1)*1+(#a_03_28  & 1)*1+(#a_03_29  & 1)*1+(#a_03_30  & 1)*1+(#a_03_31  & 1)*1+(#a_03_32  & 1)*1+(#a_03_33  & 1)*1+(#a_03_34  & 1)*1+(#a_03_35  & 1)*1+(#a_03_36  & 1)*1+(#a_03_37  & 1)*1+(#a_03_38  & 1)*1+(#a_03_39  & 1)*1+(#a_03_40  & 1)*1+(#a_03_41  & 1)*1+(#a_03_42  & 1)*1+(#a_01_43  & 1)*1+(#a_01_44  & 1)*1+(#a_03_45  & 1)*1+(#a_03_46  & 1)*1+(#a_03_47  & 1)*1+(#a_03_48  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_174{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 28 00 00 "
		
	strings :
		$a_03_0 = {00 02 00 00 8d 85 ?? ?? ff ff 50 8d 85 ?? ?? ff ff 50 ff 15 ?? ?? ?? ?? 8d 85 ?? ?? ff ff b9 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 50 8d 85 ?? ?? ff ff 68 00 02 00 00 50 e8 ?? ?? ?? ?? 83 c4 10 [0-10] 8d 85 ?? ?? ff ff 50 90 17 03 02 02 02 56 56 57 57 53 53 ff 15 ?? ?? ?? ?? ff 15 } //1
		$a_03_1 = {8a 4c 17 0c 8b c2 83 e0 03 32 4c 38 04 32 0c 38 88 0c 1a 42 3b d6 72 e8 8d 45 ?? 50 e8 } //1
		$a_03_2 = {80 38 30 0f 85 ?? ?? ?? ?? 0f b6 40 01 84 c0 0f 85 ?? ?? ?? ?? 8b de b9 ?? ?? ?? ?? 89 9d ?? ?? ?? ?? e8 } //1
		$a_03_3 = {68 3c 01 00 00 0f 42 d8 c7 85 ?? ?? ?? ?? 00 00 00 00 8d 85 ?? ?? ?? ?? 6a 00 50 e8 ?? ?? ?? ?? 83 c4 0c c7 85 ?? ?? ?? ?? 00 00 00 00 8d 85 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 50 ff 15 } //1
		$a_03_4 = {68 00 00 00 f0 6a 01 68 ?? ?? ?? ?? 6a 00 8d 8d ?? ?? ?? ?? 51 ff d0 85 c0 0f 84 ?? ?? ?? ?? 68 ff 01 00 00 } //1
		$a_03_5 = {6a 00 51 57 56 53 ff d0 8d 44 24 ?? c7 44 24 ?? 00 00 00 00 8d 1c 3e c7 44 24 ?? 00 00 00 00 50 8d 54 24 ?? 8b cb e8 } //1
		$a_03_6 = {00 02 00 00 8d 85 ?? ?? ?? ?? 50 8d 85 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? b9 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 50 8d 85 ?? ?? ?? ?? 68 00 02 00 00 50 e8 ?? ?? ?? ?? 68 ff 02 00 00 8d 85 ?? ?? ?? ?? c6 85 ?? ?? ?? ?? 00 57 50 e8 ?? ?? ?? ?? 83 c4 1c 8d 85 ?? ?? ?? ?? 57 50 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 50 57 57 ff 15 ?? ?? ?? ?? ff 15 } //1
		$a_03_7 = {00 02 00 00 8d 85 ?? ?? ?? ?? 50 8d 85 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? b9 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 50 8d 85 ?? ?? ?? ?? 68 00 02 00 00 50 e8 ?? ?? ?? ?? 83 c4 10 ff 15 ?? ?? ?? ?? b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? b9 ?? ?? ?? ?? 8b f0 e8 } //1
		$a_03_8 = {00 02 00 00 8d 44 24 ?? 50 8d 44 24 ?? 50 ff 15 ?? ?? ?? ?? 8d 44 24 ?? b9 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 50 8d 84 24 ?? ?? ?? ?? 68 00 02 00 00 50 e8 ?? ?? ?? ?? 83 c4 10 8d 84 24 ?? ?? ?? ?? 50 57 57 ff 15 ?? ?? ?? ?? ff 15 } //1
		$a_03_9 = {8b 06 8b 4e 04 6a 00 6a 00 8b 40 28 51 03 c1 ff d0 83 7e 08 00 74 ?? 57 33 ff 39 7e 0c } //1
		$a_03_10 = {66 8b 04 57 8b 7d ?? 66 83 f0 ?? 66 3b 07 8b 7d ?? 75 10 8d 46 ff 3b d0 74 1e 83 45 ?? 02 42 3b d6 7c dd 33 d2 ff 45 ?? 81 c1 ?? ?? ?? ?? 81 f9 ?? ?? ?? ?? 7c } //1
		$a_03_11 = {6a 01 6a 26 50 (53|57) ff 15 ?? ?? ?? ?? 6a 08 5a 8d 4c 24 ?? e8 ?? ?? ?? ?? [0-08] c6 84 24 ?? ?? ?? ?? 0e 83 78 14 08 72 ?? 8b 00 } //1
		$a_01_12 = {8a 54 07 0c 8b c8 83 e1 03 32 54 39 04 32 14 39 88 14 18 40 3b c6 72 e8 } //1
		$a_01_13 = {8a 54 06 0c 8b c8 83 e1 03 32 54 31 04 32 14 31 88 14 18 40 3b c7 72 e8 } //1
		$a_03_14 = {8b d3 8b c8 e8 ?? ?? ?? ?? 6a 02 6a 00 6a 00 57 ff d0 eb 06 8d 9b 00 00 00 00 68 00 20 00 00 8d 85 ?? ?? ?? ?? 6a 00 50 e8 } //1
		$a_03_15 = {68 03 80 00 00 89 5d ?? ff 15 ?? ?? ?? ?? 83 ec 0c 8b ce e8 ?? ?? ?? ?? 8b 4d ?? 89 87 ?? ?? ?? ?? 85 c9 75 0c b9 ?? ?? ?? ?? e8 } //1
		$a_01_16 = {2e 2e 5c 70 75 62 6c 69 63 5c 73 68 6f 72 74 63 75 74 73 5c 73 68 6f 72 74 63 75 74 73 5f 6d 61 6e 61 67 65 72 2e 63 63 } //1 ..\public\shortcuts\shortcuts_manager.cc
		$a_03_17 = {68 00 00 20 00 6a 00 50 e8 ?? ?? ?? ?? 8b 4c 24 ?? 8d 44 24 ?? 83 c4 0c 8b d6 50 e8 ?? ?? ?? ?? 8b 4c 24 ?? 83 c4 04 e8 ?? ?? ?? ?? 8b f0 85 f6 (74 ?? 0f 84|?? ?? ?? ?? b9) ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b d0 8b ce e8 ?? ?? ?? ?? 85 c0 74 0c 6a 00 ff d0 } //1
		$a_03_18 = {8b 73 08 33 73 04 33 33 56 e8 ?? ?? ?? ?? 8b f8 8b d6 53 8b cf e8 } //1
		$a_01_19 = {81 3a 2f 00 69 00 74 0b 46 8d 14 71 66 39 02 75 ef eb 05 e8 } //1
		$a_01_20 = {8b ca 81 e1 03 00 00 80 79 05 49 83 c9 fc 41 8a 44 17 0c 32 44 39 04 32 04 39 88 04 1a 42 3b d6 7c de } //1
		$a_01_21 = {5c 57 69 6e 53 41 50 5c 52 65 6c 65 61 73 65 5c 57 69 6e 53 41 50 2e 70 64 62 } //1 \WinSAP\Release\WinSAP.pdb
		$a_01_22 = {5c 6f 75 74 5c 52 65 6c 65 61 73 65 5c 65 78 74 65 6e 73 69 6f 6e 2e 70 64 62 } //1 \out\Release\extension.pdb
		$a_01_23 = {54 00 6f 00 6f 00 6c 00 65 00 61 00 74 00 00 00 } //1
		$a_03_24 = {68 00 00 20 00 e8 ?? ?? ?? ?? 83 c4 04 89 85 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? ?? ?? 68 00 00 20 00 6a 00 50 e8 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 50 8b d6 e8 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 83 c4 10 e8 ?? ?? ?? ?? 8b f0 85 f6 0f 84 ?? ?? ?? ?? b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b d0 8b ce e8 ?? ?? ?? ?? 85 c0 74 ?? 6a 00 ff d0 } //1
		$a_03_25 = {8b d6 8b c8 e8 ?? ?? ?? ?? 8d 8d ?? ?? ?? ?? 51 57 57 ff d0 ff 15 ?? ?? ?? ?? 85 c0 b9 01 00 00 00 0f 45 f9 } //1
		$a_03_26 = {8b d6 8b c8 e8 ?? ?? ?? ?? 6a 00 6a 00 6a 00 6a 00 6a 00 ff d0 89 44 24 ?? 85 c0 0f 84 ?? ?? ?? ?? 6a 00 68 00 00 00 04 6a 00 6a 00 53 50 ff 15 } //1
		$a_03_27 = {8b 06 8b 56 04 6a 00 6a 00 8b 40 28 52 03 c2 ff d0 [0-01] 8b ?? 04 85 ?? 74 } //1
		$a_01_28 = {00 52 75 6e 64 6c 6c 33 32 5f 44 6f 00 } //1
		$a_01_29 = {76 00 69 00 73 00 69 00 74 00 2e 00 69 00 74 00 68 00 65 00 6d 00 65 00 73 00 2e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 00 00 } //1
		$a_03_30 = {57 00 69 00 c7 05 ?? ?? ?? ?? 6e 00 53 00 c7 05 ?? ?? ?? ?? 41 00 50 00 c7 05 ?? ?? ?? ?? 53 00 76 00 c7 05 ?? ?? ?? ?? 63 00 00 00 e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 56 e8 } //1
		$a_01_31 = {47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00 47 00 55 00 49 00 44 00 28 00 34 00 31 00 34 00 46 00 32 00 35 00 39 00 37 00 2d 00 30 00 37 00 44 00 32 00 2d 00 34 00 32 00 33 00 42 00 2d 00 42 00 46 00 31 00 42 00 2d 00 33 00 41 00 38 00 44 00 39 00 38 00 42 00 46 00 43 00 33 00 42 00 35 00 29 00 } //1 Global\GUID(414F2597-07D2-423B-BF1B-3A8D98BFC3B5)
		$a_01_32 = {25 00 73 00 5f 00 41 00 4c 00 4c 00 4f 00 57 00 44 00 45 00 4c 00 5f 00 25 00 78 00 } //1 %s_ALLOWDEL_%x
		$a_01_33 = {83 7e 14 10 8b 56 10 72 04 8b 06 eb 02 8b c6 83 7e 14 10 72 02 8b 36 6a 00 6a 00 53 57 52 50 56 ff d1 b0 01 eb 02 32 c0 } //1
		$a_01_34 = {8d 48 28 8b d6 8b f3 39 19 74 01 46 81 c1 74 02 00 00 4a 75 f2 } //1
		$a_01_35 = {83 f8 01 74 05 83 f8 02 74 44 8d 45 f8 50 8d 45 f4 50 6a 00 6a 00 ff d3 83 f8 ff 75 0c 81 7d f8 47 27 00 00 75 } //1
		$a_03_36 = {53 6a 26 50 53 ff 15 90 09 4f 00 b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 53 53 ff 15 ?? ?? ?? ?? 89 44 24 ?? ff 15 ?? ?? ?? ?? 3d b7 00 00 00 0f 84 ?? ?? ?? ?? 33 c0 68 06 02 00 00 66 89 84 24 ?? ?? ?? ?? 8d 84 24 ?? ?? ?? ?? 53 50 e8 } //1
		$a_03_37 = {84 c0 74 0d e8 ?? ?? ?? ?? 6a 02 59 85 c0 0f 44 f1 8b ce e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? b9 ?? ?? ?? ?? e8 } //1
		$a_01_38 = {5c 63 68 6e 73 65 72 76 65 72 2e 70 64 62 00 } //1
		$a_03_39 = {44 00 43 00 c7 85 ?? ?? ?? ?? 37 00 34 00 c7 85 ?? ?? ?? ?? 43 00 44 00 c7 85 ?? ?? ?? ?? 35 00 2d 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1+(#a_03_6  & 1)*1+(#a_03_7  & 1)*1+(#a_03_8  & 1)*1+(#a_03_9  & 1)*1+(#a_03_10  & 1)*1+(#a_03_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_03_14  & 1)*1+(#a_03_15  & 1)*1+(#a_01_16  & 1)*1+(#a_03_17  & 1)*1+(#a_03_18  & 1)*1+(#a_01_19  & 1)*1+(#a_01_20  & 1)*1+(#a_01_21  & 1)*1+(#a_01_22  & 1)*1+(#a_01_23  & 1)*1+(#a_03_24  & 1)*1+(#a_03_25  & 1)*1+(#a_03_26  & 1)*1+(#a_03_27  & 1)*1+(#a_01_28  & 1)*1+(#a_01_29  & 1)*1+(#a_03_30  & 1)*1+(#a_01_31  & 1)*1+(#a_01_32  & 1)*1+(#a_01_33  & 1)*1+(#a_01_34  & 1)*1+(#a_01_35  & 1)*1+(#a_03_36  & 1)*1+(#a_03_37  & 1)*1+(#a_01_38  & 1)*1+(#a_03_39  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_175{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {75 46 72 6d 54 42 5f 4c 6f 6c 6c 69 70 6f 70 } //1 uFrmTB_Lollipop
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_176{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6d 00 69 00 6d 00 69 00 6b 00 61 00 74 00 7a 00 } //1 mimikatz
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_177{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {5c 53 6d 61 72 74 43 70 78 4c 69 74 65 2e 70 64 62 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_178{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {64 6c 6c 2e 70 6f 6c 79 6d 6f 72 70 68 65 64 2e 64 6c 6c } //1 dll.polymorphed.dll
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_179{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6d 61 73 74 65 72 68 61 63 6b 65 72 6d 61 73 74 65 72 68 61 6b } //1 masterhackermasterhak
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_180{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 04 01 3c 2b 74 25 3c 2f 74 1a 3c 3d 74 0f 3c 7e 74 04 88 07 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_181{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4d 61 78 28 72 61 6a 29 20 66 72 6f 6d 20 48 6f 6c 69 64 61 79 5f 32 } //1 Max(raj) from Holiday_2
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_182{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {50 53 54 65 78 74 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //1 卐敔瑸䐮䱌䐀汬慃啮汮慯乤睯
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_183{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {64 31 6f 32 6f 33 68 34 6b 35 74 36 74 37 6d 38 63 39 75 30 70 31 6b 32 69 33 75 34 74 } //1 d1o2o3h4k5t6t7m8c9u0p1k2i3u4t
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_184{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 69 6e 5a 69 70 20 32 30 31 31 } //1 WinZip 2011
		$a_01_1 = {52 55 53 53 49 41 4e 5f 43 48 41 52 53 45 54 } //1 RUSSIAN_CHARSET
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_rescan_185{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {75 73 65 72 20 61 64 64 20 3c 70 72 69 76 3e } //1 user add <priv>
		$a_01_1 = {5a 58 53 6f 63 6b 50 72 6f 78 79 } //1 ZXSockProxy
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_rescan_186{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 04 24 2f 00 00 00 ff 04 24 ff 04 24 58 05 0b 00 00 00 ff 34 07 58 03 c7 6a 1e 5e 83 ee 02 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_187{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b9 08 00 00 00 33 c0 8d 7c 24 1c f3 ab ff d6 99 b9 06 00 00 00 f7 f9 03 d1 52 8d 54 24 20 52 e8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_188{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 22 25 73 22 2c 54 53 74 61 72 74 55 70 20 30 78 32 32 20 25 73 } //1 rundll32.exe "%s",TStartUp 0x22 %s
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_189{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {77 00 73 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 5f 00 63 00 72 00 6b 00 2e 00 64 00 6c 00 6c 00 } //1 wsservice_crk.dll
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_190{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 56 47 49 44 53 41 67 65 6e 74 2e 65 78 65 } //1 AVGIDSAgent.exe
		$a_01_1 = {41 56 47 49 44 53 4d 6f 6e 69 74 6f 72 2e 65 78 65 } //1 AVGIDSMonitor.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_rescan_191{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {34 45 38 44 39 45 42 46 2d 31 32 32 43 2d 34 32 42 44 2d 41 38 43 42 2d 37 45 35 39 43 39 43 43 30 38 42 41 } //1 4E8D9EBF-122C-42BD-A8CB-7E59C9CC08BA
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_192{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {54 53 43 41 4e 49 4e 47 46 52 41 4d 45 } //1 TSCANINGFRAME
		$a_01_1 = {54 50 52 4f 43 45 53 53 4d 41 4e 41 47 45 52 46 52 41 4d 45 } //1 TPROCESSMANAGERFRAME
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_rescan_193{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 65 72 76 69 63 65 4d 61 69 6e } //1 ServiceMain
		$a_01_1 = {57 6e 4e 65 74 45 6e 74 72 79 } //1 WnNetEntry
		$a_01_2 = {6d 73 74 61 74 69 6f 6e 73 72 76 2e 64 6c 6c } //1 mstationsrv.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule _#do_exhaustivehstr_rescan_194{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2f 73 79 6e 63 2f 70 61 79 2f 3f 61 6a 61 78 3d 31 26 67 6f 3d 61 75 74 68 26 70 61 73 73 77 6f 72 64 3d 25 73 26 63 72 79 70 74 3d } //1 /sync/pay/?ajax=1&go=auth&password=%s&crypt=
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_195{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {51 57 50 72 6f 74 65 63 74 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //1
		$a_01_1 = {51 57 50 72 6f 74 65 63 74 42 48 4f } //1 QWProtectBHO
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_rescan_196{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 00 00 00 75 00 6e 00 70 00 5f 00 70 00 61 00 6d } //1
		$a_01_1 = {0d 00 00 00 66 00 63 00 5f 00 6d 00 6f 00 64 00 75 00 6c 00 65 00 5f 00 73 00 66 00 78 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_197{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {63 00 3a 00 5c 00 75 00 73 00 65 00 72 00 73 00 5c 00 50 00 75 00 62 00 6c 00 69 00 63 00 5c 00 4d 00 69 00 63 00 54 00 72 00 61 00 79 00 2e 00 6c 00 6f 00 67 00 } //1 c:\users\Public\MicTray.log
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_198{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5c 73 76 63 76 6d 78 } //1 \svcvmx
		$a_01_1 = {53 56 43 56 4d 58 7b 37 32 43 45 38 44 42 30 2d 36 45 42 36 2d 34 43 32 34 2d 39 32 45 38 2d 41 30 37 42 37 37 41 32 32 39 46 38 7d } //1 SVCVMX{72CE8DB0-6EB6-4C24-92E8-A07B77A229F8}
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_rescan_199{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 45 4c 45 43 54 5f 52 45 53 45 52 56 5f 53 52 56 5f 25 64 00 } //2
		$a_01_1 = {73 74 6f 72 2e 63 66 67 00 } //1
		$a_01_2 = {65 78 65 63 25 73 00 } //1
		$a_01_3 = {68 74 74 70 3a 2f 2f 25 64 2e 63 74 72 6c 2e 25 73 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}
rule _#do_exhaustivehstr_rescan_200{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 00 74 00 68 00 75 00 6d 00 62 00 73 00 2e 00 64 00 62 00 } //1 .thumbs.db
		$a_01_1 = {74 00 61 00 72 00 67 00 65 00 74 00 2e 00 6c 00 6e 00 6b 00 } //1 target.lnk
		$a_01_2 = {64 00 65 00 73 00 6b 00 74 00 6f 00 70 00 2e 00 69 00 6e 00 69 00 } //1 desktop.ini
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule _#do_exhaustivehstr_rescan_201{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR,01 00 01 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 65 6c 65 61 73 65 5c 61 72 63 5f 32 30 31 30 2e 70 64 62 } //1 Release\arc_2010.pdb
		$a_01_1 = {52 65 6c 65 61 73 65 5c 6e 65 77 5f 61 72 63 2e 70 64 62 } //1 Release\new_arc.pdb
		$a_01_2 = {52 65 6c 65 61 73 65 5c 61 72 63 5f 32 30 30 35 2e 70 64 62 } //1 Release\arc_2005.pdb
		$a_01_3 = {43 50 61 79 6d 65 6e 74 46 6f 72 6d } //1 CPaymentForm
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_202{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR,14 00 14 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 70 72 6f 6a 65 63 74 5c 41 7a 75 72 65 5f 47 55 49 5c 44 65 62 75 67 5c 41 7a 75 72 65 5f 47 55 49 2e 70 64 62 } //10 \project\Azure_GUI\Debug\Azure_GUI.pdb
		$a_01_1 = {68 65 6c 6c 6f 68 65 6c 6c 6f 68 65 6c 6c 6f 68 65 6c 6c 6f } //10 hellohellohellohello
		$a_01_2 = {67 66 64 65 72 74 66 67 68 6a 6b 75 79 72 74 67 } //10 gfdertfghjkuyrtg
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10) >=20
 
}
rule _#do_exhaustivehstr_rescan_203{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 68 65 6c 6c 20 73 65 74 75 70 20 69 6e 66 6f 72 6d 61 74 69 6f 6e 3a } //1 shell setup information:
		$a_01_1 = {75 70 74 69 6d 65 3a 20 25 2d 2e 32 64 20 64 61 79 73 20 25 2d 2e 32 64 20 68 6f 75 72 73 20 25 2d 2e 32 64 20 6d 69 6e 75 74 65 73 20 25 2d 2e 32 64 20 73 65 63 6f 6e 64 73 } //1 uptime: %-.2d days %-.2d hours %-.2d minutes %-.2d seconds
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_rescan_204{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 00 43 00 20 00 44 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 00 00 } //1
		$a_01_1 = {4e 00 6f 00 45 00 6e 00 74 00 69 00 72 00 65 00 4e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 00 00 } //1
		$a_01_2 = {70 00 72 00 6f 00 63 00 6b 00 69 00 6c 00 6c 00 36 00 34 00 2e 00 65 00 78 00 65 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_rescan_205{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR,04 00 04 00 08 00 00 "
		
	strings :
		$a_01_0 = {78 36 34 2e 7a 69 70 } //1 x64.zip
		$a_01_1 = {78 33 32 2e 7a 69 70 } //1 x32.zip
		$a_01_2 = {2c 61 64 6d 69 6e 3d } //1 ,admin=
		$a_01_3 = {2c 67 75 69 64 3d } //1 ,guid=
		$a_01_4 = {5c 00 42 00 79 00 70 00 61 00 73 00 73 00 } //1 \Bypass
		$a_01_5 = {5c 00 67 00 75 00 69 00 64 00 2e 00 6c 00 6f 00 67 00 } //1 \guid.log
		$a_01_6 = {63 74 2e 7a 69 70 } //1 ct.zip
		$a_01_7 = {63 74 2e 65 78 65 } //1 ct.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=4
 
}
rule _#do_exhaustivehstr_rescan_206{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {4d 69 63 72 6f 73 6f 66 74 20 4f 66 66 69 63 65 00 00 00 00 45 72 72 6f 20 61 6f 20 61 62 72 69 72 20 6f 20 61 72 71 75 69 76 6f 2c 6f 75 20 6f } //1
		$a_01_1 = {4d 69 63 72 6f 73 6f 66 74 20 4f 66 66 69 63 65 00 00 00 00 46 61 6c 68 61 20 61 6f 20 61 62 72 69 72 20 6f 20 61 72 71 75 69 76 6f 20 6f 75 20 6f } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_207{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {42 00 61 00 6e 00 63 00 6f 00 20 00 53 00 61 00 6e 00 74 00 61 00 6e 00 64 00 65 00 72 00 20 00 42 00 72 00 61 00 73 00 69 00 6c 00 20 00 7c 00 20 00 42 00 61 00 6e 00 63 00 6f 00 20 00 64 00 6f 00 20 00 6a 00 75 00 6e 00 74 00 6f 00 73 00 20 00 2d 00 20 00 4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 20 00 46 00 69 00 72 00 65 00 66 00 6f 00 78 00 } //1 Banco Santander Brasil | Banco do juntos - Mozilla Firefox
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_exhaustivehstr_rescan_208{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {44 00 4c 00 4c 00 00 00 00 00 00 00 00 00 4d 5a } //1
		$a_01_1 = {53 50 4f 52 44 45 52 2e 64 6c 6c 00 57 53 43 57 72 69 74 65 4e 61 6d 65 53 70 61 63 65 4f 72 64 65 72 00 57 53 43 57 72 69 74 65 50 72 6f 76 69 64 65 72 4f 72 64 65 72 00 } //1
		$a_01_2 = {43 75 72 72 65 6e 74 5f 4e 61 6d 65 53 70 61 63 65 5f 43 61 74 61 6c 6f 67 } //1 Current_NameSpace_Catalog
		$a_01_3 = {73 70 6f 72 64 65 72 2e 70 64 62 } //1 sporder.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule _#do_exhaustivehstr_rescan_209{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 44 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 5c 00 52 00 65 00 61 00 6c 00 2d 00 54 00 69 00 6d 00 65 00 20 00 50 00 72 00 6f 00 74 00 65 00 63 00 74 00 69 00 6f 00 6e 00 } //1 Windows Defender\Real-Time Protection
		$a_01_1 = {4e 00 6f 00 74 00 69 00 66 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 5f 00 53 00 75 00 70 00 70 00 72 00 65 00 73 00 73 00 } //1 Notification_Suppress
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule _#do_exhaustivehstr_rescan_210{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {ba 94 17 40 00 8b c7 e8 13 31 00 00 8b d0 8b 06 e8 e6 31 00 00 } //1
		$a_01_1 = {a3 ac 25 41 00 ba a0 17 40 00 8b c7 e8 f9 30 00 00 8b d0 8b 06 e8 cc 31 00 00 } //1
		$a_01_2 = {a3 b0 25 41 00 ba ac 17 40 00 8b c7 e8 df 30 00 00 8b d0 8b 06 e8 b2 31 00 00 } //1
		$a_01_3 = {a3 b4 25 41 00 ba b8 17 40 00 8b c7 e8 c5 30 00 00 8b d0 8b 06 e8 98 31 00 00 a3 b8 25 41 00 ba c4 17 40 00 8b c7 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}
rule _#do_exhaustivehstr_rescan_211{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 5c 00 41 00 64 00 76 00 61 00 6e 00 63 00 65 00 64 00 5c 00 } //1 Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\
		$a_01_1 = {53 00 68 00 6f 00 77 00 53 00 75 00 70 00 65 00 72 00 48 00 69 00 64 00 64 00 65 00 6e 00 } //1 ShowSuperHidden
		$a_01_2 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 5c 00 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run\
		$a_01_3 = {2e 00 76 00 62 00 70 00 } //1 .vbp
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule _#do_exhaustivehstr_rescan_212{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR,0f 00 0f 00 04 00 00 "
		
	strings :
		$a_01_0 = {6c 00 6f 00 67 00 69 00 6e 00 3d 00 25 00 73 00 26 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 3d 00 25 00 73 00 } //5 login=%s&password=%s
		$a_01_1 = {26 00 63 00 6f 00 6e 00 73 00 65 00 6e 00 74 00 5f 00 61 00 63 00 63 00 65 00 70 00 74 00 3d 00 47 00 72 00 61 00 6e 00 74 00 2b 00 61 00 63 00 63 00 65 00 73 00 73 00 2b 00 74 00 6f 00 2b 00 42 00 6f 00 78 00 26 00 72 00 65 00 71 00 75 00 65 00 73 00 74 00 5f 00 74 00 6f 00 6b 00 65 00 6e 00 3d 00 25 00 73 00 } //5 &consent_accept=Grant+access+to+Box&request_token=%s
		$a_01_2 = {6c 00 6f 00 67 00 69 00 6e 00 5f 00 73 00 75 00 62 00 6d 00 69 00 74 00 3d 00 41 00 75 00 74 00 68 00 6f 00 72 00 69 00 7a 00 69 00 6e 00 67 00 2e 00 2e 00 2e 00 26 00 64 00 6f 00 6c 00 6f 00 67 00 69 00 6e 00 3d 00 31 00 26 00 63 00 6c 00 69 00 65 00 6e 00 74 00 5f 00 69 00 64 00 3d 00 25 00 73 00 } //5 login_submit=Authorizing...&dologin=1&client_id=%s
		$a_01_3 = {62 00 6f 00 78 00 5f 00 76 00 69 00 73 00 69 00 74 00 6f 00 72 00 5f 00 69 00 64 00 3d 00 25 00 73 00 3b 00 20 00 62 00 76 00 3d 00 25 00 73 00 3b 00 20 00 63 00 6e 00 3d 00 25 00 73 00 3b 00 } //5 box_visitor_id=%s; bv=%s; cn=%s;
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5) >=15
 
}
rule _#do_exhaustivehstr_rescan_213{
	meta:
		description = "!#do_exhaustivehstr_rescan,SIGNATURE_TYPE_PEHSTR,01 00 01 00 04 00 00 "
		
	strings :
		$a_01_0 = {4c 00 6f 00 63 00 61 00 6c 00 5c 00 7b 00 45 00 33 00 38 00 39 00 33 00 41 00 42 00 46 00 2d 00 35 00 33 00 45 00 30 00 2d 00 34 00 32 00 32 00 38 00 2d 00 39 00 41 00 32 00 37 00 2d 00 31 00 43 00 36 00 39 00 46 00 42 00 31 00 44 00 36 00 37 00 43 00 32 00 7d 00 } //1 Local\{E3893ABF-53E0-4228-9A27-1C69FB1D67C2}
		$a_01_1 = {4c 00 6f 00 63 00 61 00 6c 00 5c 00 7b 00 31 00 42 00 46 00 39 00 30 00 44 00 41 00 37 00 2d 00 42 00 34 00 32 00 34 00 2d 00 34 00 33 00 62 00 66 00 2d 00 41 00 45 00 42 00 41 00 2d 00 41 00 43 00 45 00 34 00 34 00 32 00 41 00 34 00 44 00 34 00 32 00 39 00 7d 00 } //1 Local\{1BF90DA7-B424-43bf-AEBA-ACE442A4D429}
		$a_01_2 = {4c 00 6f 00 63 00 61 00 6c 00 5c 00 7b 00 38 00 37 00 36 00 31 00 41 00 35 00 32 00 35 00 2d 00 38 00 38 00 39 00 31 00 2d 00 34 00 66 00 31 00 62 00 2d 00 38 00 35 00 41 00 46 00 2d 00 32 00 42 00 43 00 35 00 45 00 42 00 31 00 32 00 32 00 33 00 38 00 41 00 7d 00 } //1 Local\{8761A525-8891-4f1b-85AF-2BC5EB12238A}
		$a_01_3 = {4c 00 6f 00 63 00 61 00 6c 00 5c 00 7b 00 30 00 41 00 42 00 31 00 46 00 41 00 41 00 38 00 2d 00 37 00 42 00 31 00 31 00 2d 00 34 00 32 00 39 00 31 00 2d 00 42 00 43 00 43 00 44 00 2d 00 36 00 36 00 36 00 39 00 45 00 38 00 44 00 44 00 31 00 37 00 46 00 36 00 7d 00 } //1 Local\{0AB1FAA8-7B11-4291-BCCD-6669E8DD17F6}
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=1
 
}