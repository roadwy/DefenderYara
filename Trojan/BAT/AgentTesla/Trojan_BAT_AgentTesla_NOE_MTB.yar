
rule Trojan_BAT_AgentTesla_NOE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NOE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {02 f4 02 0f 03 ef 02 3d 72 eb 02 3d 72 3d 72 e3 02 3d 72 3d 72 cd 02 cd 02 d6 02 3d 72 ea 02 05 03 3d 72 3d 72 3d 72 3d 72 df 02 ef } //01 00 
		$a_01_1 = {02 18 03 df 02 e1 02 d2 02 df 02 eb 02 3d 72 13 03 df 02 e2 02 3d 72 3d 72 3d 72 3d 72 3d 72 3d 72 3d 72 3d 72 3d 72 3d 72 3d 72 3d 72 } //01 00 
		$a_01_2 = {23 00 47 00 65 00 74 00 23 00 4d 00 65 00 74 00 23 00 68 00 6f 00 64 00 } //01 00  #Get#Met#hod
		$a_01_3 = {24 61 61 30 63 34 35 62 38 2d 63 63 35 38 2d 34 66 64 37 2d 39 32 62 37 2d 64 66 31 39 34 33 64 35 33 64 66 } //01 00  $aa0c45b8-cc58-4fd7-92b7-df1943d53df
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 } //00 00  FromBase64
	condition:
		any of ($a_*)
 
}