
rule Backdoor_Win64_Havoc_A_MTB{
	meta:
		description = "Backdoor:Win64/Havoc.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {48 63 d0 48 8b 45 20 48 01 d0 0f b6 08 8b 45 f8 48 63 d0 48 8b 45 10 48 01 d0 44 89 c2 31 ca 88 10 83 45 fc 01 83 45 f8 01 8b 45 f8 3b 45 18 } //00 00 
	condition:
		any of ($a_*)
 
}