
rule Trojan_Win32_Gozi_RL_MTB{
	meta:
		description = "Trojan:Win32/Gozi.RL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b d1 2b d0 2b 54 24 04 8a 12 88 11 ba ff ff ff ff 2b d0 01 54 24 08 8d 4c 01 01 75 e3 } //00 00 
	condition:
		any of ($a_*)
 
}