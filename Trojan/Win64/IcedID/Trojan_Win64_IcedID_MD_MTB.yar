
rule Trojan_Win64_IcedID_MD_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {f7 ea c1 fa 90 01 01 89 c8 c1 f8 90 01 01 29 c2 89 d0 01 c0 89 c2 c1 e2 90 01 01 01 d0 29 c1 89 c8 48 63 d0 48 8b 85 90 01 04 48 01 d0 0f b6 00 44 31 c8 41 88 00 83 85 90 01 04 01 8b 95 90 01 04 8b 85 90 01 04 39 c2 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_MD_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {50 6c 75 67 69 6e 49 6e 69 74 } //01 00  PluginInit
		$a_01_1 = {41 6b 71 45 57 2e 64 6c 6c } //01 00  AkqEW.dll
		$a_01_2 = {4a 72 69 61 41 44 76 50 37 64 4c } //01 00  JriaADvP7dL
		$a_01_3 = {5a 47 6e 55 32 42 71 42 67 70 70 } //01 00  ZGnU2BqBgpp
		$a_01_4 = {68 4f 6e 34 32 65 62 62 33 } //01 00  hOn42ebb3
		$a_01_5 = {73 30 4a 72 70 79 64 54 61 71 70 } //00 00  s0JrpydTaqp
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_MD_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {48 89 44 24 08 48 8b 44 24 30 eb 00 48 ff c8 48 89 44 24 30 eb 92 eb 9e 48 8b 44 24 28 48 89 44 24 08 eb 84 48 8b 44 24 20 48 89 04 24 66 3b ed 74 e6 88 08 48 8b 04 24 66 3b ff 74 9d } //05 00 
		$a_01_1 = {68 69 61 75 73 66 62 75 73 6a 61 66 6b 68 79 61 73 6a 66 6b } //00 00  hiausfbusjafkhyasjfk
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_MD_MTB_4{
	meta:
		description = "Trojan:Win64/IcedID.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 89 04 24 48 8b 44 24 08 eb e9 48 8b 44 24 40 48 ff c8 eb 28 48 8b 04 24 48 ff c0 eb e2 4c 89 44 24 18 48 89 54 24 10 eb bf 48 8b 44 24 38 48 89 44 24 08 eb 21 8a 09 88 08 eb d9 } //01 00 
		$a_01_1 = {69 66 78 64 64 70 2e 64 6c 6c 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 45 70 48 55 48 55 4d 46 45 69 67 48 6f 75 } //00 00 
	condition:
		any of ($a_*)
 
}