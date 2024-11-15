
rule TrojanDropper_Win32_Cutwail_CCIO_MTB{
	meta:
		description = "TrojanDropper:Win32/Cutwail.CCIO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 ab aa aa aa f7 e6 8b c6 c1 ea 04 8d 0c 52 c1 e1 03 2b c1 8a 4c 04 14 8b 44 24 10 32 8e ?? ?? ?? ?? 88 0c 06 46 3b 74 24 2c 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}