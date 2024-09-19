
rule Backdoor_Win32_Mokes_GNK_MTB{
	meta:
		description = "Backdoor:Win32/Mokes.GNK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 59 8a 4d fc 03 c3 30 08 83 7d 0c 0f } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}
rule Backdoor_Win32_Mokes_GNK_MTB_2{
	meta:
		description = "Backdoor:Win32/Mokes.GNK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c6 30 08 83 7d 0c 0f ?? ?? 57 ff 75 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}