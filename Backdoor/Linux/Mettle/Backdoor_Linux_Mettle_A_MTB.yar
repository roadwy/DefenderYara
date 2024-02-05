
rule Backdoor_Linux_Mettle_A_MTB{
	meta:
		description = "Backdoor:Linux/Mettle.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {81 c3 71 84 0d 00 c7 45 90 00 00 00 00 8d 7d 94 b9 0a 00 00 00 31 c0 f3 aa 8d 7d b3 b9 35 00 00 00 f3 aa 8d 7d 9e b9 15 00 00 00 f3 aa be 01 00 00 00 3b 75 14 } //00 00 
	condition:
		any of ($a_*)
 
}