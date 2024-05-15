
rule TrojanDropper_Win32_Small_HNS_MTB{
	meta:
		description = "TrojanDropper:Win32/Small.HNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {00 73 0b 0f b6 02 42 34 90 01 01 88 01 41 eb ed 90 00 } //01 00 
		$a_03_1 = {6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 90 01 01 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}