
rule Backdoor_Win32_Mokes_GTT_MTB{
	meta:
		description = "Backdoor:Win32/Mokes.GTT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f8 40 89 45 f8 83 7d f8 0d ?? ?? 8b 45 f8 0f be 44 05 cc 83 f0 ?? 8b 4d f8 88 44 0d cc } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}