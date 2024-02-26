
rule Trojan_Win32_Zombie_RB_MTB{
	meta:
		description = "Trojan:Win32/Zombie.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 30 08 57 00 30 22 46 00 d0 f7 19 00 2a 5e 58 77 00 } //00 00 
	condition:
		any of ($a_*)
 
}