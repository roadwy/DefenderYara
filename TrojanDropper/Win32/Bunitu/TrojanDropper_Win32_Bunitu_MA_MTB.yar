
rule TrojanDropper_Win32_Bunitu_MA_MTB{
	meta:
		description = "TrojanDropper:Win32/Bunitu.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 c4 08 eb 90 01 01 8b 15 90 01 04 52 e8 90 01 04 83 c4 04 e8 90 01 04 83 3d 90 01 05 75 90 09 09 00 6a 90 01 01 6a 90 01 01 e8 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}