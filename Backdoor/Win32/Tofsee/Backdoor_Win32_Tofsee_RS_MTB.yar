
rule Backdoor_Win32_Tofsee_RS_MTB{
	meta:
		description = "Backdoor:Win32/Tofsee.RS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {e8 1b fe ff ff 30 04 3e b8 01 00 00 00 29 44 24 90 01 01 8b 74 24 90 01 01 85 f6 79 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}