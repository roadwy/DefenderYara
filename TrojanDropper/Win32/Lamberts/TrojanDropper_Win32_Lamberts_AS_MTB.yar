
rule TrojanDropper_Win32_Lamberts_AS_MTB{
	meta:
		description = "TrojanDropper:Win32/Lamberts.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 4c 24 04 8b 01 69 c0 ?? ?? ?? ?? 05 39 30 00 00 89 01 c1 e8 10 25 } //1
		$a_00_1 = {32 04 3a 59 88 06 46 42 80 7d 10 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}