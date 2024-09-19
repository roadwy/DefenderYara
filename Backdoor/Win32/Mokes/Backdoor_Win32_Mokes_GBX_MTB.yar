
rule Backdoor_Win32_Mokes_GBX_MTB{
	meta:
		description = "Backdoor:Win32/Mokes.GBX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 f1 6b ca ?? 83 e1 07 d3 e6 0b de 88 5d fc 0f b6 45 fc 35 ?? ?? ?? ?? 88 45 fc 0f b6 45 fc } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}