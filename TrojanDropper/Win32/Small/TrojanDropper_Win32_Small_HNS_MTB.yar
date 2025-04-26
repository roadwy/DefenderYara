
rule TrojanDropper_Win32_Small_HNS_MTB{
	meta:
		description = "TrojanDropper:Win32/Small.HNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 73 0b 0f b6 02 42 34 ?? 88 01 41 eb ed } //1
		$a_03_1 = {6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 ?? e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}