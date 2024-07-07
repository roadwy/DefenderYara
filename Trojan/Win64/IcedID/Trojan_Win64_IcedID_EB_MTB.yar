
rule Trojan_Win64_IcedID_EB_MTB{
	meta:
		description = "Trojan:Win64/IcedID.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c2 48 8d 49 01 83 e0 07 ff c2 0f b6 44 30 10 30 41 ff } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}
rule Trojan_Win64_IcedID_EB_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 40 b9 ab 01 00 00 2b c8 8b 45 40 2b c8 83 c1 2b 89 4d 40 8a 45 48 88 02 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win64_IcedID_EB_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d fc ba 4f ec c4 4e 89 c8 f7 ea c1 fa 04 89 c8 c1 f8 1f 29 c2 89 d0 6b c0 34 29 c1 89 c8 } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}
rule Trojan_Win64_IcedID_EB_MTB_4{
	meta:
		description = "Trojan:Win64/IcedID.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff c2 41 8b cd 49 81 c8 1f 21 af 04 48 63 c2 48 81 f1 d2 3b 00 00 4c 89 83 00 02 00 00 48 3b c1 72 de } //6
	condition:
		((#a_01_0  & 1)*6) >=6
 
}
rule Trojan_Win64_IcedID_EB_MTB_5{
	meta:
		description = "Trojan:Win64/IcedID.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 54 24 10 48 89 4c 24 08 eb 1b 80 44 24 40 5a c6 44 24 41 4b eb b8 80 44 24 46 30 c6 44 24 47 22 e9 6d ff ff ff } //8
	condition:
		((#a_01_0  & 1)*8) >=8
 
}
rule Trojan_Win64_IcedID_EB_MTB_6{
	meta:
		description = "Trojan:Win64/IcedID.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {79 67 61 67 69 68 73 66 67 79 75 6b 61 73 6a 68 67 79 6a 61 73 } //10 ygagihsfgyukasjhgyjas
		$a_01_1 = {10 00 00 00 00 00 80 01 00 00 00 00 10 00 00 00 02 00 00 06 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}
rule Trojan_Win64_IcedID_EB_MTB_7{
	meta:
		description = "Trojan:Win64/IcedID.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_01_0 = {e9 50 fc ff ff 66 89 84 24 8e 00 00 00 b8 15 00 00 00 eb 00 83 c0 5b 66 89 84 24 90 00 00 00 eb 17 83 c0 2c 66 89 84 24 8c 00 00 00 eb 00 b8 3c 00 00 00 83 c0 33 eb cd } //8
	condition:
		((#a_01_0  & 1)*8) >=8
 
}
rule Trojan_Win64_IcedID_EB_MTB_8{
	meta:
		description = "Trojan:Win64/IcedID.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4d 6b 61 6a 64 73 61 73 64 } //1 Mkajdsasd
		$a_01_1 = {48 69 64 65 43 6f 69 6e } //1 HideCoin
		$a_01_2 = {63 6f 6f 6b 69 65 58 } //1 cookieX
		$a_01_3 = {6f 66 66 6c 69 6e 65 69 63 } //1 offlineic
		$a_01_4 = {65 6d 61 69 6c 7c 73 65 4c 6f 61 64 69 6e 67 } //1 email|seLoading
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win64_IcedID_EB_MTB_9{
	meta:
		description = "Trojan:Win64/IcedID.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4d 68 48 6b 44 4f 50 41 57 44 4d } //1 MhHkDOPAWDM
		$a_01_1 = {50 41 69 56 68 67 44 65 79 4f 63 } //1 PAiVhgDeyOc
		$a_01_2 = {50 6c 75 67 69 6e 49 6e 69 74 } //1 PluginInit
		$a_01_3 = {51 4b 67 4b 55 4e 65 73 42 6e 76 55 78 64 } //1 QKgKUNesBnvUxd
		$a_01_4 = {52 62 59 62 75 72 42 53 53 6b 50 6b 4a } //1 RbYburBSSkPkJ
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win64_IcedID_EB_MTB_10{
	meta:
		description = "Trojan:Win64/IcedID.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {75 61 69 73 64 6e 68 61 73 64 69 61 6b 6a 73 64 6e 61 69 73 73 } //1 uaisdnhasdiakjsdnaiss
		$a_01_1 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //1 WaitForSingleObject
		$a_01_2 = {43 72 65 61 74 65 45 76 65 6e 74 57 } //1 CreateEventW
		$a_01_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Trojan_Win64_IcedID_EB_MTB_11{
	meta:
		description = "Trojan:Win64/IcedID.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {48 75 4a 54 51 7a 71 63 72 63 42 6c 6f 56 4d } //1 HuJTQzqcrcBloVM
		$a_01_1 = {4a 62 61 64 73 6a 61 73 66 6b 73 } //1 Jbadsjasfks
		$a_01_2 = {66 61 71 52 6a 47 48 62 61 79 75 66 47 55 } //1 faqRjGHbayufGU
		$a_01_3 = {47 65 74 4d 65 6e 75 49 74 65 6d 49 6e 66 6f 41 } //1 GetMenuItemInfoA
		$a_01_4 = {52 65 6c 65 61 73 65 44 43 } //1 ReleaseDC
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win64_IcedID_EB_MTB_12{
	meta:
		description = "Trojan:Win64/IcedID.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 89 4c 24 20 4c 89 44 24 18 eb aa 80 44 24 44 67 c6 44 24 45 27 eb aa 80 44 24 46 13 c6 44 24 47 37 e9 e5 fe ff ff 48 8d 94 24 88 00 00 00 48 8b 4c 24 38 e9 49 fd ff ff 44 8b 4c 24 60 4c 8d 84 24 80 00 00 00 eb df b8 01 00 00 00 83 c0 00 eb 38 } //8
	condition:
		((#a_01_0  & 1)*8) >=8
 
}
rule Trojan_Win64_IcedID_EB_MTB_13{
	meta:
		description = "Trojan:Win64/IcedID.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {79 67 75 61 73 64 6d 61 69 75 73 64 68 79 61 67 73 75 6e 6d 6a 75 69 61 73 68 79 64 } //5 yguasdmaiusdhyagsunmjuiashyd
		$a_01_1 = {79 67 69 68 61 73 6e 68 66 75 79 61 73 66 6a 6e 61 73 68 75 79 64 6a 61 73 64 6e 61 } //5 ygihasnhfuyasfjnashuydjasdna
		$a_01_2 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //1 WaitForSingleObject
		$a_01_3 = {43 72 65 61 74 65 45 76 65 6e 74 57 } //1 CreateEventW
		$a_01_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}
rule Trojan_Win64_IcedID_EB_MTB_14{
	meta:
		description = "Trojan:Win64/IcedID.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {61 61 79 75 73 64 67 68 69 6a 61 73 6f 6a 69 66 75 68 79 67 61 68 73 6a 64 6b 61 73 61 73 } //5 aayusdghijasojifuhygahsjdkasas
		$a_01_1 = {61 79 75 73 64 68 69 6f 64 73 66 75 69 6f 69 73 64 6f 66 6a 67 64 6f 69 64 67 6f 69 6a 73 } //5 ayusdhiodsfuioisdofjgdoidgoijs
		$a_01_2 = {4f 70 65 6e 50 72 6f 63 65 73 73 } //1 OpenProcess
		$a_01_3 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 49 64 } //1 GetCurrentProcessId
		$a_01_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}
rule Trojan_Win64_IcedID_EB_MTB_15{
	meta:
		description = "Trojan:Win64/IcedID.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {75 6e 6b 6a 61 64 73 75 68 79 61 67 66 73 62 64 68 61 6a 64 6a 61 69 73 75 66 68 61 6a 73 } //5 unkjadsuhyagfsbdhajdjaisufhajs
		$a_01_1 = {79 69 75 61 6e 6a 75 69 67 68 79 64 73 69 6a 6b 73 61 6b 69 64 73 6a 75 66 6a 6b 64 73 73 } //5 yiuanjuighydsijksakidsjufjkdss
		$a_01_2 = {44 75 70 6c 69 63 61 74 65 48 61 6e 64 6c 65 } //1 DuplicateHandle
		$a_01_3 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 } //1 GetCurrentProcess
		$a_01_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}
rule Trojan_Win64_IcedID_EB_MTB_16{
	meta:
		description = "Trojan:Win64/IcedID.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {6c 69 62 67 64 2e 64 6c 6c } //10 libgd.dll
		$a_01_1 = {68 44 5f 43 4f 4c 4f 52 5f 4d 41 50 5f 58 31 31 } //1 hD_COLOR_MAP_X11
		$a_01_2 = {68 5a 4e 32 47 44 35 49 6d 61 67 65 31 30 43 72 65 61 74 65 46 72 6f 6d 45 50 36 5f 69 6f 62 75 66 } //1 hZN2GD5Image10CreateFromEP6_iobuf
		$a_01_3 = {68 5a 4e 32 47 44 35 49 6d 61 67 65 31 30 43 72 65 61 74 65 46 72 6f 6d 45 52 53 69 } //1 hZN2GD5Image10CreateFromERSi
		$a_01_4 = {68 5a 4e 32 47 44 35 49 6d 61 67 65 31 30 43 72 65 61 74 65 46 72 6f 6d 45 69 50 76 } //1 hZN2GD5Image10CreateFromEiPv
		$a_01_5 = {68 64 41 66 66 69 6e 65 41 70 70 6c 79 54 6f 50 6f 69 6e 74 46 } //1 hdAffineApplyToPointF
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}
rule Trojan_Win64_IcedID_EB_MTB_17{
	meta:
		description = "Trojan:Win64/IcedID.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_01_0 = {62 68 75 6e 6e 6e 6e 64 75 61 68 73 64 69 6f 6a 61 73 64 79 67 61 6a 61 6b 73 73 } //5 bhunnnnduahsdiojasdygajakss
		$a_01_1 = {74 79 75 69 6a 69 61 73 64 6a 75 61 73 6a 64 61 6b 73 64 61 73 61 } //5 tyuijiasdjuasjdaksdasa
		$a_01_2 = {74 6e 73 6a 75 79 61 67 73 64 62 68 6a 6e 67 6a 69 66 6f 6d 61 6a 64 75 61 68 79 } //5 tnsjuyagsdbhjngjifomajduahy
		$a_01_3 = {64 75 67 69 6e 6a 61 73 75 68 79 67 75 66 61 69 6a 61 73 6e 66 68 79 75 61 73 68 } //5 duginjasuhygufaijasnfhyuash
		$a_01_4 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //1 WaitForSingleObject
		$a_01_5 = {43 72 65 61 74 65 45 76 65 6e 74 } //1 CreateEvent
		$a_01_6 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=8
 
}
rule Trojan_Win64_IcedID_EB_MTB_18{
	meta:
		description = "Trojan:Win64/IcedID.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 08 00 00 "
		
	strings :
		$a_01_0 = {54 42 53 79 4d 6e 63 2e 64 6c 6c } //10 TBSyMnc.dll
		$a_01_1 = {43 5a 58 5a 41 50 6d 2e 64 6c 6c } //10 CZXZAPm.dll
		$a_01_2 = {68 44 49 43 54 5f 61 64 64 45 6e 74 72 6f 70 79 54 61 62 6c 65 73 46 72 6f 6d 42 75 66 66 65 72 } //1 hDICT_addEntropyTablesFromBuffer
		$a_01_3 = {68 44 49 43 54 5f 66 69 6e 61 6c 69 7a 65 44 69 63 74 69 6f 6e 61 72 79 } //1 hDICT_finalizeDictionary
		$a_01_4 = {68 53 54 44 5f 44 43 74 78 5f 67 65 74 50 61 72 61 6d 65 74 65 72 } //1 hSTD_DCtx_getParameter
		$a_01_5 = {68 53 54 44 5f 44 43 74 78 5f 6c 6f 61 64 44 69 63 74 69 6f 6e 61 72 79 } //1 hSTD_DCtx_loadDictionary
		$a_01_6 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_7 = {56 69 72 74 75 61 6c 51 75 65 72 79 } //1 VirtualQuery
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=16
 
}
rule Trojan_Win64_IcedID_EB_MTB_19{
	meta:
		description = "Trojan:Win64/IcedID.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 00 64 00 79 00 47 00 61 00 6c 00 6c 00 65 00 72 00 79 00 29 00 2e 00 31 00 36 00 32 00 75 00 61 00 62 00 6f 00 75 00 74 00 62 00 6c 00 75 00 65 00 61 00 72 00 65 00 66 00 69 00 72 00 73 00 74 00 6c 00 } //1 sdyGallery).162uaboutbluearefirstl
		$a_01_1 = {30 00 75 00 73 00 65 00 73 00 69 00 74 00 30 00 } //1 0usesit0
		$a_01_2 = {76 00 62 00 72 00 6f 00 77 00 73 00 65 00 72 00 73 00 51 00 62 00 75 00 74 00 } //1 vbrowsersQbut
		$a_01_3 = {73 00 63 00 6f 00 72 00 65 00 73 00 35 00 39 00 70 00 72 00 65 00 63 00 69 00 73 00 65 00 68 00 6a 00 70 00 61 00 67 00 65 00 6f 00 6e 00 } //1 scores59precisehjpageon
		$a_01_4 = {6a 00 4a 00 49 00 68 00 6f 00 6d 00 65 00 76 00 69 00 6e 00 70 00 72 00 69 00 6e 00 63 00 65 00 31 00 34 00 } //1 jJIhomevinprince14
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win64_IcedID_EB_MTB_20{
	meta:
		description = "Trojan:Win64/IcedID.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 00 62 00 69 00 6e 00 5c 00 57 00 69 00 58 00 5c 00 54 00 65 00 73 00 74 00 5c 00 74 00 65 00 73 00 74 00 2e 00 63 00 73 00 } //1 \bin\WiX\Test\test.cs
		$a_01_1 = {74 00 65 00 73 00 74 00 2e 00 63 00 73 00 2e 00 64 00 6c 00 6c 00 } //1 test.cs.dll
		$a_01_2 = {7a 00 7a 00 7a 00 7a 00 49 00 6e 00 76 00 6f 00 6b 00 65 00 4d 00 61 00 6e 00 61 00 67 00 65 00 64 00 43 00 75 00 73 00 74 00 6f 00 6d 00 41 00 63 00 74 00 69 00 6f 00 6e 00 4f 00 75 00 74 00 4f 00 66 00 50 00 72 00 6f 00 63 00 } //1 zzzzInvokeManagedCustomActionOutOfProc
		$a_01_3 = {74 00 65 00 73 00 74 00 2e 00 63 00 73 00 21 00 58 00 58 00 58 00 2e 00 59 00 79 00 59 00 2e 00 5a 00 7a 00 5a 00 } //1 test.cs!XXX.YyY.ZzZ
		$a_01_4 = {52 00 65 00 6d 00 6f 00 74 00 65 00 4d 00 73 00 69 00 53 00 65 00 73 00 73 00 69 00 6f 00 6e 00 } //1 RemoteMsiSession
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}