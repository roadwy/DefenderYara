
rule Backdoor_Win32_Mokes_GZF_MTB{
	meta:
		description = "Backdoor:Win32/Mokes.GZF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 40 89 45 fc 83 7d fc 0d 90 01 02 8b 45 fc 0f be 44 05 dc 35 90 01 04 8b 4d fc 88 44 0d dc 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}