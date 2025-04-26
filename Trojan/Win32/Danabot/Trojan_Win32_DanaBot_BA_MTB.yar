
rule Trojan_Win32_DanaBot_BA_MTB{
	meta:
		description = "Trojan:Win32/DanaBot.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff ff 8a 09 88 08 eb ?? 81 3d ?? ?? ?? ?? 32 09 00 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_DanaBot_BA_MTB_2{
	meta:
		description = "Trojan:Win32/DanaBot.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {30 04 31 b8 [0-20] 83 f0 ?? 83 ad [0-30] 39 bd [0-30] 90 13 [0-20] 8b 8d } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}