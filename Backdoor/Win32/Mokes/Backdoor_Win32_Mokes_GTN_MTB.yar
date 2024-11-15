
rule Backdoor_Win32_Mokes_GTN_MTB{
	meta:
		description = "Backdoor:Win32/Mokes.GTN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 55 c8 0f b6 02 35 94 00 00 00 8b 0d ?? ?? ?? ?? 03 4d c8 88 01 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}