
rule Backdoor_Win32_Mokes_GXZ_MTB{
	meta:
		description = "Backdoor:Win32/Mokes.GXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {30 14 30 83 7d 90 01 01 0f 90 01 02 6a 00 6a 00 57 8d 85 90 01 04 50 53 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}