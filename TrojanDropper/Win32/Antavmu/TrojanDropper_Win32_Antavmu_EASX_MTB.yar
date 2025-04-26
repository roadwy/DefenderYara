
rule TrojanDropper_Win32_Antavmu_EASX_MTB{
	meta:
		description = "TrojanDropper:Win32/Antavmu.EASX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 64 24 00 8a 14 38 80 ea 7a 80 f2 19 88 14 38 40 3b c3 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}