
rule Backdoor_Linux_Gyfgyt_BS_MTB{
	meta:
		description = "Backdoor:Linux/Gyfgyt.BS!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {00 62 10 21 af c2 00 0c 8f 82 80 18 90 02 05 8c 43 24 b8 8f c2 00 0c 90 02 05 00 43 10 2b 10 40 00 0d 90 02 05 8f c2 00 0c 90 02 05 24 42 00 01 af c2 00 0c 8f 82 80 18 90 02 05 8c 42 24 b8 90 02 05 24 43 00 01 8f 82 80 18 90 02 05 ac 43 24 b8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}