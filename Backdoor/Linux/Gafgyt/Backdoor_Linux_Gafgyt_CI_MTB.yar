
rule Backdoor_Linux_Gafgyt_CI_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.CI!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {ec 31 12 51 13 62 14 72 ba 91 ec 31 23 11 60 d1 0b 41 09 00 0d 62 b3 91 ec 31 12 51 04 71 21 21 5d d1 12 } //00 00 
	condition:
		any of ($a_*)
 
}