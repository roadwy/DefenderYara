
rule Trojan_Win64_IcedID_MI_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {4d 63 c2 4d 8d 5b 01 48 8b c7 41 ff c2 49 f7 e0 48 c1 ea ?? 48 6b ca ?? 4c 2b c1 42 0f b6 44 84 20 41 30 43 ff 41 81 fa ?? ?? ?? ?? 72 d2 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win64_IcedID_MI_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.MI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 44 24 20 48 89 04 24 66 3b ed 74 ?? 88 08 48 8b 04 24 3a db 74 ?? 48 ff c0 48 89 04 24 66 3b d2 74 } //5
		$a_01_1 = {79 75 67 68 6f 69 61 73 64 6d 69 61 6f 73 64 6e 75 61 73 64 6a 6b 61 } //5 yughoiasdmiaosdnuasdjka
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}
rule Trojan_Win64_IcedID_MI_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.MI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0b 00 00 "
		
	strings :
		$a_01_0 = {50 6c 75 67 69 6e 49 6e 69 74 } //10 PluginInit
		$a_01_1 = {44 42 43 7a 63 48 } //1 DBCzcH
		$a_01_2 = {4e 78 52 78 73 34 31 30 } //1 NxRxs410
		$a_01_3 = {4f 76 6a 47 46 45 78 76 64 64 68 } //1 OvjGFExvddh
		$a_01_4 = {55 37 52 6d 54 41 42 33 57 35 } //1 U7RmTAB3W5
		$a_01_5 = {49 47 4e 41 2e 64 6c 6c } //1 IGNA.dll
		$a_01_6 = {71 65 55 4d 6e 63 2e 64 6c 6c } //1 qeUMnc.dll
		$a_01_7 = {45 58 33 41 4c 31 32 6c 4f 49 } //1 EX3AL12lOI
		$a_01_8 = {49 47 6c 76 52 6c 6c 35 63 6e } //1 IGlvRll5cn
		$a_01_9 = {4e 6b 77 6d 30 71 } //1 Nkwm0q
		$a_01_10 = {59 53 6f 55 68 56 41 69 64 31 } //1 YSoUhVAid1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=15
 
}