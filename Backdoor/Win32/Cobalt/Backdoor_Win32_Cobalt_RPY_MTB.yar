
rule Backdoor_Win32_Cobalt_RPY_MTB{
	meta:
		description = "Backdoor:Win32/Cobalt.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 c1 89 ca 8b 45 dc 8d 48 02 8b 45 d4 01 c8 88 10 83 45 dc 03 83 45 e0 04 8b 45 d8 83 e8 02 39 45 e0 0f 8c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}