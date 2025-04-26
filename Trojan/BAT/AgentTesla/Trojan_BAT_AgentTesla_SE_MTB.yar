
rule Trojan_BAT_AgentTesla_SE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_81_0 = {52 65 6a 6f 69 63 65 52 65 66 52 65 73 68 69 6e 67 2e 72 65 73 6f 75 72 63 65 73 } //2 RejoiceRefReshing.resources
		$a_81_1 = {24 32 63 62 30 62 62 31 66 2d 38 38 37 66 2d 34 66 34 38 2d 61 62 38 66 2d 39 35 62 37 65 39 64 32 30 37 61 66 } //2 $2cb0bb1f-887f-4f48-ab8f-95b7e9d207af
		$a_81_2 = {4b 4a 43 77 4c 59 4d 4d 62 55 44 78 43 4e 52 6b } //2 KJCwLYMMbUDxCNRk
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2) >=6
 
}