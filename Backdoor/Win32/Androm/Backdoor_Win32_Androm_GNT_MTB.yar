
rule Backdoor_Win32_Androm_GNT_MTB{
	meta:
		description = "Backdoor:Win32/Androm.GNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 04 39 8a 04 10 88 04 39 41 81 f9 60 26 00 00 72 ?? 8b 15 ?? ?? ?? ?? 8b cb 0f b6 04 31 8a 04 10 88 04 31 41 81 f9 00 b4 05 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}