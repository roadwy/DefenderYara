
rule Trojan_Win64_IcedID_MS_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 c7 40 18 2f 6b 48 8b f1 eb d3 48 89 70 20 57 eb 15 0f b6 c1 0f 46 d0 eb 00 42 88 54 04 20 49 ff c0 e9 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win64_IcedID_MS_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {36 70 4d 6a 76 72 2e 64 6c 6c } //10 6pMjvr.dll
		$a_01_1 = {75 69 6a 6e 73 64 76 66 62 67 73 7a } //1 uijnsdvfbgsz
		$a_01_2 = {58 6a 46 52 69 33 65 4c 66 72 46 } //1 XjFRi3eLfrF
		$a_01_3 = {45 42 6a 57 61 77 } //1 EBjWaw
		$a_01_4 = {56 57 44 52 34 37 69 79 75 } //1 VWDR47iyu
		$a_01_5 = {6d 55 4c 30 5a 48 6c 6f 55 61 4a } //1 mUL0ZHloUaJ
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}
rule Trojan_Win64_IcedID_MS_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_01_0 = {75 61 79 67 73 68 69 64 6a 75 64 73 68 79 67 61 68 73 69 6a 6f 64 61 6a 73 66 75 61 73 6a 6b 66 61 73 } //10 uaygshidjudshygahsijodajsfuasjkfas
		$a_01_1 = {79 67 75 61 73 68 69 6e 64 6a 61 69 75 73 68 64 79 66 75 68 69 61 73 6f 64 6a 75 68 79 67 61 68 73 6a 6b 73 64 } //10 yguashindjaiushdyfuhiasodjuhygahsjksd
		$a_01_2 = {79 75 67 61 65 6e 6a 61 6b 64 73 75 68 79 67 66 72 75 68 6a 77 65 6b 75 68 65 77 62 79 75 6a 61 73 73 } //10 yugaenjakdsuhygfruhjwekuhewbyujass
		$a_01_3 = {18 00 00 00 2a 03 00 00 00 00 00 00 10 00 00 00 10 00 00 00 00 00 80 01 00 00 00 00 10 00 00 00 02 00 00 06 } //5
		$a_01_4 = {44 75 70 6c 69 63 61 74 65 48 61 6e 64 6c 65 } //2 DuplicateHandle
		$a_01_5 = {57 61 69 74 46 6f 72 4d 75 6c 74 69 70 6c 65 4f 62 6a 65 63 74 73 45 78 } //2 WaitForMultipleObjectsEx
		$a_01_6 = {43 72 65 61 74 65 45 76 65 6e 74 57 } //2 CreateEventW
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*5+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2) >=21
 
}