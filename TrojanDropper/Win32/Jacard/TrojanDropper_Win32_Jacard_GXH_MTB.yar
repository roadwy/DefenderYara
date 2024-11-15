
rule TrojanDropper_Win32_Jacard_GXH_MTB{
	meta:
		description = "TrojanDropper:Win32/Jacard.GXH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 04 24 30 44 24 01 8d 54 24 01 8b c5 b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 43 4e } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}