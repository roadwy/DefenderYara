
rule Backdoor_Linux_Gafgyt_BV_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.BV!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {81 3f 00 0c 38 09 00 01 90 90 1f 00 0c 80 1f 00 0c 7c 09 03 78 80 1f 00 18 7d 29 02 14 88 09 00 00 54 00 06 3e 7c 03 03 78 4c c6 31 82 48 90 02 05 7c 60 1b 78 2f 80 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}