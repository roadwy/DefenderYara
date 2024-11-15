
rule Backdoor_Win32_Mokes_GZT_MTB{
	meta:
		description = "Backdoor:Win32/Mokes.GZT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {30 14 38 83 fb ?? ?? ?? 6a 00 8d 85 ?? ?? ?? ?? 50 6a 00 ff 15 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}