
rule Backdoor_Linux_Gafgyt_CR_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.CR!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {c1 fa 0f 89 c8 c1 f8 1f 89 d3 29 c3 89 d8 89 45 c0 8b 45 c0 } //01 00 
		$a_00_1 = {48 f7 e1 48 89 c8 48 29 d0 48 d1 e8 48 8d 04 02 48 89 c2 48 c1 ea 05 } //01 00 
		$a_00_2 = {48 c1 eb 05 48 89 9d 10 fe ff ff 48 8b 85 10 fe ff ff 48 c1 e0 02 48 8d 14 c5 00 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}