
rule Backdoor_Linux_Gyfgyt_BR_MTB{
	meta:
		description = "Backdoor:Linux/Gyfgyt.BR!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {48 50 3d 20 10 02 39 29 90 02 04 55 40 10 3a 7d 90 01 01 4a 14 91 69 00 00 3d 20 10 02 39 29 90 02 04 55 40 10 3a 7d 90 01 01 4a 14 80 09 00 00 7c 03 03 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}