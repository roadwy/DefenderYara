
rule Backdoor_Linux_Gafgyt_AC_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.AC!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4b 69 6c 6c 65 72 20 69 73 20 6f 6e } //01 00  Killer is on
		$a_01_1 = {52 65 70 6f 72 74 20 4b 69 6c 6c 73 20 69 73 20 6f 6e } //01 00  Report Kills is on
		$a_01_2 = {4c 6f 63 6b 65 72 20 69 73 20 6f 6e } //01 00  Locker is on
		$a_00_3 = {62 6f 74 6b 69 6c 6c } //00 00  botkill
	condition:
		any of ($a_*)
 
}