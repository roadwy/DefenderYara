
rule Trojan_Win32_Qakbot_DA_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d e8 83 e9 37 0f b7 45 f8 99 03 c8 88 4d ff 8b 15 90 01 04 81 c2 d4 b4 08 01 89 15 90 01 04 a1 90 01 04 03 45 f4 8b 0d 90 01 04 89 88 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_DA_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {33 c8 8b 45 08 eb 90 01 01 0f b6 08 8b 45 fc eb 90 01 01 40 89 45 fc eb 90 00 } //2
		$a_03_1 = {8b 45 08 03 45 fc eb 90 01 01 55 8b ec eb 90 01 01 99 f7 7d 14 eb 90 01 01 8b 45 10 0f b6 04 10 eb c7 03 45 fc 88 08 eb 90 00 } //2
		$a_01_2 = {61 6f 72 62 69 73 5f 73 79 6e 74 68 65 73 69 73 5f 74 72 61 63 6b 6f 6e 6c 79 } //1 aorbis_synthesis_trackonly
		$a_01_3 = {61 6f 72 62 69 73 5f 73 79 6e 74 68 65 73 69 73 5f 62 6c 6f 63 6b 69 6e } //1 aorbis_synthesis_blockin
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}