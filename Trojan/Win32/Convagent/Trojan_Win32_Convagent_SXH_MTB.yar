
rule Trojan_Win32_Convagent_SXH_MTB{
	meta:
		description = "Trojan:Win32/Convagent.SXH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 04 00 00 "
		
	strings :
		$a_03_0 = {8d 85 e8 f7 ff ff 50 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 03 c0 50 68 ?? ?? ?? ?? 57 ff 15 } //20
		$a_01_1 = {99 b9 9f 86 01 00 f7 f9 8d 85 f4 fd ff ff 52 } //10
		$a_80_2 = {25 73 5c 6d 61 63 4f 53 78 } //%s\macOSx  5
		$a_80_3 = {64 2e 77 73 66 } //d.wsf  5
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*10+(#a_80_2  & 1)*5+(#a_80_3  & 1)*5) >=40
 
}