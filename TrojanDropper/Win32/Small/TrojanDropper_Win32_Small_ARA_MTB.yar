
rule TrojanDropper_Win32_Small_ARA_MTB{
	meta:
		description = "TrojanDropper:Win32/Small.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 18 0f b6 84 24 bc 00 00 00 30 02 89 f8 42 03 84 24 bd 00 00 00 39 c2 eb e6 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}