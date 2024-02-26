
rule Trojan_BAT_AgentTesla_SX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {24 39 33 44 32 39 30 36 32 2d 39 45 36 31 2d 34 41 41 43 2d 42 32 38 36 2d 41 45 43 30 31 37 39 41 43 45 46 31 } //01 00  $93D29062-9E61-4AAC-B286-AEC0179ACEF1
		$a_81_1 = {53 74 75 62 5c 50 72 6f 6a 65 63 74 73 5c 43 6f 6e 66 69 66 6f 72 6d 73 79 61 6c 6c 61 5c 6f 62 6a 5c 44 65 62 75 67 5c 43 6f 6e 66 69 66 6f 72 6d 73 79 61 6c 6c 61 2e 70 64 62 } //01 00  Stub\Projects\Confiformsyalla\obj\Debug\Confiformsyalla.pdb
		$a_81_2 = {59 6f 75 20 68 61 76 65 20 62 65 65 6e 20 68 61 63 6b 65 64 20 62 79 20 43 6f 6e 66 69 66 6f 72 6d 73 79 61 6c 6c 61 } //01 00  You have been hacked by Confiformsyalla
		$a_81_3 = {43 6f 6e 66 69 66 6f 72 6d 73 79 61 6c 6c 61 2e 65 78 65 } //00 00  Confiformsyalla.exe
	condition:
		any of ($a_*)
 
}