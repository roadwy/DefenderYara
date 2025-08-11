
rule Backdoor_Win32_Tofsee_GNQ_MTB{
	meta:
		description = "Backdoor:Win32/Tofsee.GNQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 ea 89 55 ?? 8b 45 ?? 03 45 ?? 89 45 ?? 8b 4d ?? 33 4d ?? 89 4d ?? 81 3d ?? ?? ?? ?? c1 10 00 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}