
rule Trojan_Win32_Tedy_ABTD_MTB{
	meta:
		description = "Trojan:Win32/Tedy.ABTD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_03_0 = {42 0f b6 46 05 89 55 ec 0f b6 80 ?? ?? ?? ?? c0 c8 03 32 c1 88 46 05 0f b6 46 06 0f b6 80 ?? ?? ?? ?? c0 c8 03 32 c3 88 46 06 0f b6 46 07 0f b6 80 ?? ?? ?? ?? c0 c8 03 32 45 f0 88 46 07 3b 55 d8 } //5
		$a_03_1 = {8b c1 f7 f6 0f b6 c1 03 55 ?? 6b c0 ?? 32 02 88 04 0f 41 83 f9 } //4
		$a_80_2 = {4c 6f 67 54 72 61 63 6b 45 76 65 6e 74 44 61 74 61 } //LogTrackEventData  1
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*4+(#a_80_2  & 1)*1) >=10
 
}