
rule Backdoor_Win32_Tofsee_AMAF_MTB{
	meta:
		description = "Backdoor:Win32/Tofsee.AMAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 ec 31 45 fc 33 55 fc 89 55 d4 8b 45 d4 83 45 f8 64 29 45 f8 83 6d f8 64 8b 55 f8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}