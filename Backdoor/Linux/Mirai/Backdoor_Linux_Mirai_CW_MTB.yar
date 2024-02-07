
rule Backdoor_Linux_Mirai_CW_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.CW!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 32 65 6b 63 76 2e 6d 6f 6f 6f 2e 63 6f 6d } //01 00  u2ekcv.mooo.com
		$a_01_1 = {7b 63 7a 64 6f 74 26 22 6e 65 65 7a 64 7d 74 38 3d 3f 31 74 } //01 00  {czdot&"neezd}t8=?1t
		$a_01_2 = {74 65 64 7a 64 6f 74 } //01 00  tedzdot
		$a_01_3 = {7b 61 67 63 7a 67 62 74 7c } //00 00  {agczgbt|
	condition:
		any of ($a_*)
 
}