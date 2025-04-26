
rule Trojan_Win64_IcedID_BA_MTB{
	meta:
		description = "Trojan:Win64/IcedID.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 89 4c 24 08 48 83 ec 28 eb 00 48 8b 44 24 30 48 89 44 24 08 eb 28 48 8b 44 24 08 48 ff c0 eb d3 8a 09 88 08 eb } //3
		$a_01_1 = {69 79 61 68 73 75 66 79 67 61 73 75 66 69 68 6b 61 6a 73 6b 66 75 68 61 73 79 68 66 61 6a 61 } //1 iyahsufygasufihkajskfuhasyhfaja
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}
rule Trojan_Win64_IcedID_BA_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b c1 0f b7 4c 24 ?? 3a d2 74 ?? 66 89 44 24 ?? 48 ?? ?? ?? ?? ?? ?? ?? 66 3b c9 74 ?? 33 c8 8b c1 66 3b c9 74 } //1
		$a_03_1 = {8b c0 3a ff 74 ?? 8b 44 24 ?? f7 b4 24 ?? ?? ?? ?? 66 3b c9 74 ?? 89 84 24 ?? ?? ?? ?? 33 d2 66 3b f6 74 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}