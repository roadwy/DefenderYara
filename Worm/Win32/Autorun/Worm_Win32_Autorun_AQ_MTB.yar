
rule Worm_Win32_Autorun_AQ_MTB{
	meta:
		description = "Worm:Win32/Autorun.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 41 00 ab 33 41 00 d4 33 41 00 e0 33 41 00 09 34 41 00 1a 35 41 00 3f 35 41 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}