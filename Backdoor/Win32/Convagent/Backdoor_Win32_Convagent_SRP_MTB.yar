
rule Backdoor_Win32_Convagent_SRP_MTB{
	meta:
		description = "Backdoor:Win32/Convagent.SRP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 55 08 81 c2 9f 04 00 00 89 55 08 8b 45 08 33 d2 b9 4e 01 00 00 f7 f1 89 45 08 66 b9 15 00 66 b8 00 00 66 81 f3 f8 00 66 8b c3 e2 } //00 00 
	condition:
		any of ($a_*)
 
}