
rule Trojan_BAT_AgentTesla_FD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.FD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_00_0 = {03 08 18 5a 58 0d 02 09 91 1e 62 02 09 17 58 91 58 13 04 11 04 05 61 13 04 07 08 11 04 d1 9d 00 08 17 58 0c 05 17 58 10 03 08 06 fe 04 13 05 11 05 2d cc } //10
		$a_81_1 = {47 5a 69 70 53 74 72 65 61 6d } //1 GZipStream
		$a_81_2 = {47 65 74 42 69 74 6d 61 70 } //1 GetBitmap
		$a_81_3 = {67 65 74 5f 4b 65 79 } //1 get_Key
		$a_81_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_5 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
	condition:
		((#a_00_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=15
 
}
rule Trojan_BAT_AgentTesla_FD_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.FD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 3a 2f 2f 31 38 35 2e 32 34 36 2e 32 32 30 2e 36 35 2f 6c 65 65 2f 43 68 64 63 65 73 70 62 6b 61 68 2e 6a 70 65 67 } //1 http://185.246.220.65/lee/Chdcespbkah.jpeg
		$a_81_1 = {48 6f 6f 78 74 6c 6d 76 73 6e 66 } //1 Hooxtlmvsnf
		$a_81_2 = {44 6e 76 65 67 77 77 6f 68 6a 2e 41 75 70 7a 69 6b 6f 78 7a 69 6f 77 76 66 73 6b 6e 66 62 77 69 7a 71 77 } //1 Dnvegwwohj.Aupzikoxziowvfsknfbwizqw
		$a_81_3 = {50 78 6f 6e 71 67 74 68 78 62 62 73 63 69 6e 75 77 68 65 77 6a 75 77 75 } //1 Pxonqgthxbbscinuwhewjuwu
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule Trojan_BAT_AgentTesla_FD_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.FD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 11 00 00 "
		
	strings :
		$a_81_0 = {24 66 62 37 37 32 37 62 64 2d 35 63 64 32 2d 34 39 63 31 2d 39 34 31 35 2d 36 32 30 37 36 30 34 65 61 65 33 31 } //20 $fb7727bd-5cd2-49c1-9415-6207604eae31
		$a_81_1 = {24 63 38 61 32 30 39 37 37 2d 35 35 65 37 2d 34 34 65 39 2d 38 65 34 32 2d 65 66 63 39 62 66 39 33 38 35 31 61 } //20 $c8a20977-55e7-44e9-8e42-efc9bf93851a
		$a_81_2 = {24 61 61 38 35 66 34 66 35 2d 39 36 36 31 2d 34 35 33 36 2d 62 31 34 64 2d 37 38 66 36 63 66 36 31 62 61 32 62 } //20 $aa85f4f5-9661-4536-b14d-78f6cf61ba2b
		$a_81_3 = {24 65 64 65 32 33 34 32 35 2d 38 63 61 61 2d 34 63 35 30 2d 39 31 35 66 2d 30 33 65 64 35 31 64 66 34 34 62 66 } //20 $ede23425-8caa-4c50-915f-03ed51df44bf
		$a_81_4 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_81_5 = {43 68 75 72 63 68 5f 50 72 6f 6a 65 63 74 6f 72 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //1 Church_Projector.My.Resources
		$a_81_6 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
		$a_81_7 = {53 74 61 72 45 67 67 43 6f 6e 74 72 6f 6c 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //1 StarEggControl.My.Resources
		$a_81_8 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //1 DebuggerStepThroughAttribute
		$a_81_9 = {53 68 6f 70 5f 4d 61 6e 61 67 65 72 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //1 Shop_Manager.My.Resources
		$a_81_10 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_81_11 = {49 6e 74 65 72 66 61 63 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 Interface.Properties.Resources
		$a_81_12 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_13 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_81_14 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
		$a_81_15 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_16 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*20+(#a_81_2  & 1)*20+(#a_81_3  & 1)*20+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1+(#a_81_14  & 1)*1+(#a_81_15  & 1)*1+(#a_81_16  & 1)*1) >=24
 
}