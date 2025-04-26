
rule Trojan_Win64_IcedID_AM_MTB{
	meta:
		description = "Trojan:Win64/IcedID.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {42 55 75 70 52 45 5a 39 64 63 } //2 BUupREZ9dc
		$a_01_1 = {44 30 63 4c 68 37 33 5a 69 6b 34 } //2 D0cLh73Zik4
		$a_01_2 = {47 4e 6c 50 64 44 } //2 GNlPdD
		$a_01_3 = {5a 74 61 38 58 62 57 4a 79 79 6a } //2 Zta8XbWJyyj
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}
rule Trojan_Win64_IcedID_AM_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_01_0 = {44 75 75 54 67 62 71 } //2 DuuTgbq
		$a_01_1 = {50 4a 51 6a 64 63 66 } //2 PJQjdcf
		$a_01_2 = {57 48 52 49 32 48 32 } //2 WHRI2H2
		$a_01_3 = {57 54 66 32 45 38 } //2 WTf2E8
		$a_01_4 = {57 58 6d 4e 51 57 69 51 63 64 } //2 WXmNQWiQcd
		$a_01_5 = {68 66 64 66 61 73 64 66 63 } //2 hfdfasdfc
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=12
 
}
rule Trojan_Win64_IcedID_AM_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 "
		
	strings :
		$a_01_0 = {43 58 42 6a 55 2e 64 6c 6c } //10 CXBjU.dll
		$a_01_1 = {4a 58 62 49 67 4b 30 } //1 JXbIgK0
		$a_01_2 = {4b 78 45 59 72 52 4c 47 74 6f 75 } //1 KxEYrRLGtou
		$a_01_3 = {52 53 32 61 39 71 31 32 35 } //1 RS2a9q125
		$a_01_4 = {52 56 33 5a 53 33 } //1 RV3ZS3
		$a_01_5 = {54 64 33 55 74 70 34 36 31 } //1 Td3Utp461
		$a_01_6 = {50 6c 75 67 69 6e 49 6e 69 74 } //1 PluginInit
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=16
 
}
rule Trojan_Win64_IcedID_AM_MTB_4{
	meta:
		description = "Trojan:Win64/IcedID.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_01_0 = {41 52 41 4e 38 46 46 4f 47 59 45 } //3 ARAN8FFOGYE
		$a_01_1 = {41 5a 6e 67 31 76 7a 4e } //3 AZng1vzN
		$a_01_2 = {41 76 32 72 43 6b 6c 79 79 7a 75 } //3 Av2rCklyyzu
		$a_01_3 = {43 61 6c 6c 57 69 6e 64 6f 77 50 72 6f 63 57 } //3 CallWindowProcW
		$a_01_4 = {52 61 73 44 69 61 6c 57 } //3 RasDialW
		$a_01_5 = {52 61 73 45 6e 75 6d 43 6f 6e 6e 65 63 74 69 6f 6e 73 57 } //3 RasEnumConnectionsW
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*3) >=18
 
}
rule Trojan_Win64_IcedID_AM_MTB_5{
	meta:
		description = "Trojan:Win64/IcedID.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_01_1 = {64 67 45 61 66 77 } //1 dgEafw
		$a_01_2 = {53 74 67 43 72 65 61 74 65 44 6f 63 66 69 6c 65 4f 6e 49 4c 6f 63 6b 42 79 74 65 73 } //1 StgCreateDocfileOnILockBytes
		$a_01_3 = {43 72 65 61 74 65 49 4c 6f 63 6b 42 79 74 65 73 4f 6e 48 47 6c 6f 62 61 6c } //1 CreateILockBytesOnHGlobal
		$a_01_4 = {48 74 6d 6c 48 65 6c 70 57 } //1 HtmlHelpW
		$a_01_5 = {68 68 63 74 72 6c 2e 6f 63 78 } //1 hhctrl.ocx
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule Trojan_Win64_IcedID_AM_MTB_6{
	meta:
		description = "Trojan:Win64/IcedID.AM!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 0a 48 ff c2 41 88 08 4d 8d 40 01 48 83 e8 01 75 ed 45 0f b7 4d 14 45 0f b7 55 06 49 83 c1 2c 4d 85 d2 74 45 4d 03 cd 0f 1f 80 00 00 00 00 41 8b 49 f8 49 ff ca 41 8b 11 49 03 ce 45 8b 41 fc 48 03 d5 4d 85 c0 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}