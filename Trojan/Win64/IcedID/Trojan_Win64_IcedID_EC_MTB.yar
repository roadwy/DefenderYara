
rule Trojan_Win64_IcedID_EC_MTB{
	meta:
		description = "Trojan:Win64/IcedID.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 43 58 48 8b 83 a8 00 00 00 41 8b d0 c1 ea 10 88 14 01 41 8b d0 ff 43 6c } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win64_IcedID_EC_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {67 79 75 61 73 68 6e 6a 68 73 79 66 68 6a 61 } //10 gyuashnjhsyfhja
		$a_01_1 = {10 00 00 00 00 00 80 01 00 00 00 00 10 00 00 00 02 00 00 06 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}
rule Trojan_Win64_IcedID_EC_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 89 4c 24 20 4c 89 44 24 18 eb 64 b8 09 00 00 00 83 c0 03 eb 23 83 c0 1c 66 89 44 24 50 eb 0f c7 44 24 44 00 00 00 00 b8 01 00 00 00 eb 28 } //8
	condition:
		((#a_01_0  & 1)*8) >=8
 
}
rule Trojan_Win64_IcedID_EC_MTB_4{
	meta:
		description = "Trojan:Win64/IcedID.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 79 61 73 62 64 68 6e 61 68 73 64 79 75 61 6a 73 64 6b 61 } //2 tyasbdhnahsdyuajsdka
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //2 VirtualAlloc
		$a_01_2 = {78 63 61 6e 65 73 69 35 66 65 72 73 38 6c 6f 70 64 79 74 73 } //1 xcanesi5fers8lopdyts
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}
rule Trojan_Win64_IcedID_EC_MTB_5{
	meta:
		description = "Trojan:Win64/IcedID.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4d 61 67 73 6a 64 62 61 68 73 64 6a 73 } //1 Magsjdbahsdjs
		$a_01_1 = {68 4a 6e 43 78 43 70 6a 64 45 47 49 54 65 75 } //1 hJnCxCpjdEGITeu
		$a_01_2 = {6c 4b 6b 4b 62 63 57 69 4e 71 74 44 74 } //1 lKkKbcWiNqtDt
		$a_01_3 = {52 65 67 69 73 74 65 72 43 6c 61 73 73 45 78 57 } //1 RegisterClassExW
		$a_01_4 = {47 65 74 46 6f 63 75 73 } //1 GetFocus
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win64_IcedID_EC_MTB_6{
	meta:
		description = "Trojan:Win64/IcedID.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_01_1 = {52 65 63 6f 72 64 73 65 6e 74 65 6e 63 65 } //1 Recordsentence
		$a_01_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_01_3 = {54 6f 74 61 6c 73 65 6e 73 65 5c 62 6f 64 79 2e 70 64 62 } //1 Totalsense\body.pdb
		$a_01_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win64_IcedID_EC_MTB_7{
	meta:
		description = "Trojan:Win64/IcedID.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {52 47 5a 6c 71 69 78 6f 63 74 50 67 57 43 42 63 } //1 RGZlqixoctPgWCBc
		$a_01_1 = {55 61 58 56 42 53 64 76 6a 70 53 73 62 6f } //1 UaXVBSdvjpSsbo
		$a_01_2 = {62 74 51 73 79 68 63 65 72 68 4e 4e 62 44 6d 7a } //1 btQsyhcerhNNbDmz
		$a_01_3 = {68 4a 6a 44 4f 48 6c 57 42 6b 55 43 71 67 61 51 } //1 hJjDOHlWBkUCqgaQ
		$a_01_4 = {69 75 61 73 64 75 79 75 61 67 73 64 6a 61 73 61 73 73 } //1 iuasduyuagsdjasass
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win64_IcedID_EC_MTB_8{
	meta:
		description = "Trojan:Win64/IcedID.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {49 6e 69 74 69 61 6c 69 7a 65 43 72 69 74 69 63 61 6c 53 65 63 74 69 6f 6e 45 78 } //1 InitializeCriticalSectionEx
		$a_01_1 = {4c 43 4d 61 70 53 74 72 69 6e 67 45 78 } //1 LCMapStringEx
		$a_01_2 = {4c 6f 63 61 6c 65 4e 61 6d 65 54 6f 4c 43 49 44 } //1 LocaleNameToLCID
		$a_01_3 = {45 58 42 73 2e 64 6c 6c } //1 EXBs.dll
		$a_01_4 = {41 33 46 66 74 46 } //1 A3FftF
		$a_01_5 = {41 33 59 44 7a 66 62 43 54 } //1 A3YDzfbCT
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule Trojan_Win64_IcedID_EC_MTB_9{
	meta:
		description = "Trojan:Win64/IcedID.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {69 68 61 73 75 6e 64 69 6a 64 73 75 68 79 67 62 68 6a 73 6b 64 66 73 69 75 66 6b 6a 64 73 61 69 73 6a 6f 61 73 } //5 ihasundijdsuhygbhjskdfsiufkjdsaisjoas
		$a_01_1 = {67 79 75 61 73 69 66 69 69 73 64 79 67 61 69 73 6a 64 6f 69 66 67 75 68 79 75 67 61 73 6a 73 6a 75 68 } //5 gyuasifiisdygaisjdoifguhyugasjsjuh
		$a_01_2 = {4f 70 65 6e 50 72 6f 63 65 73 73 } //1 OpenProcess
		$a_01_3 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 49 64 } //1 GetCurrentProcessId
		$a_01_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}
rule Trojan_Win64_IcedID_EC_MTB_10{
	meta:
		description = "Trojan:Win64/IcedID.EC!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f af d1 44 31 f2 83 ca fe 44 39 f2 0f 94 c1 83 f8 0a 0f 9c c3 30 cb b9 ec 7d 1b 2b bd ec 7d 1b 2b 75 05 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}
rule Trojan_Win64_IcedID_EC_MTB_11{
	meta:
		description = "Trojan:Win64/IcedID.EC!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 44 24 23 0f b6 c0 8a 4c 24 20 0f b6 c9 33 c8 8b c1 88 44 24 20 8a 44 24 23 fe c0 88 44 24 23 48 8b 44 24 38 8a 4c 24 20 88 08 48 8b 44 24 38 48 ff c0 48 89 44 24 38 8b 44 24 28 ff c8 89 44 24 28 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}