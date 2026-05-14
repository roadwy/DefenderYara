
rule TrojanDropper_Win64_Fragtor_ARAX_MTB{
	meta:
		description = "TrojanDropper:Win64/Fragtor.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 85 2c 07 00 00 48 98 0f b6 84 05 c8 04 00 00 83 f0 7f 8b 95 2c 07 00 00 48 63 d2 88 84 15 c8 04 00 00 83 85 2c 07 00 00 01 83 bd 2c 07 00 00 07 7e cd } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}