
rule Trojan_Win64_IcedID_MJ_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {4c 2b c0 66 66 66 0f 1f 84 00 00 00 00 00 41 0f b6 0c 00 88 08 48 8d 40 01 83 ea 01 75 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_MJ_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.MJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {50 6c 75 67 69 6e 49 6e 69 74 } //01 00  PluginInit
		$a_01_1 = {4a 4d 77 71 2e 64 6c 6c } //01 00  JMwq.dll
		$a_01_2 = {42 4c 67 53 5a 6e 4a 47 68 } //01 00  BLgSZnJGh
		$a_01_3 = {43 4b 4b 4f 4c 36 41 59 66 62 } //01 00  CKKOL6AYfb
		$a_01_4 = {57 4c 73 51 62 78 4b 31 35 } //01 00  WLsQbxK15
		$a_01_5 = {64 4b 69 33 42 54 59 38 4d 33 76 } //00 00  dKi3BTY8M3v
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_MJ_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.MJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {75 73 69 61 66 6e 75 79 75 61 73 66 62 68 73 62 66 61 73 6a 64 6a 6b 61 } //01 00  usiafnuyuasfbhsbfasjdjka
		$a_01_1 = {42 42 64 5a 75 6a 62 48 68 55 68 42 41 57 } //01 00  BBdZujbHhUhBAW
		$a_01_2 = {44 70 77 45 4d 4d 49 43 5a 7a 6d 48 70 72 44 } //01 00  DpwEMMICZzmHprD
		$a_01_3 = {49 62 53 4b 79 67 41 71 53 77 67 62 46 4c 77 } //01 00  IbSKygAqSwgbFLw
		$a_01_4 = {56 5a 50 4f 61 6a 74 62 6c 42 4c 66 63 } //01 00  VZPOajtblBLfc
		$a_01_5 = {5a 74 53 52 79 6c 77 45 5a 67 4b 79 56 74 5a } //00 00  ZtSRylwEZgKyVtZ
	condition:
		any of ($a_*)
 
}