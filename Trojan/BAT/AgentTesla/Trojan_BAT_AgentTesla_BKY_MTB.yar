
rule Trojan_BAT_AgentTesla_BKY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BKY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_02_0 = {06 02 07 6f 90 01 03 0a 03 07 03 6f 90 01 03 0a 5d 6f 90 01 03 0a 61 d1 6f 90 01 03 0a 26 00 07 17 58 0b 07 02 6f 90 01 03 0a fe 04 0c 08 2d 90 00 } //10
		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_2 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_81_3 = {69 30 41 4e 42 5a 57 4f 58 6f 4c 45 43 67 49 46 33 77 69 47 41 5a 70 42 58 67 3d } //1 i0ANBZWOXoLECgIF3wiGAZpBXg=
		$a_81_4 = {52 73 63 4c 68 59 69 49 6a 34 63 5a 43 78 42 4c 78 67 32 42 41 59 30 47 6e 51 50 50 51 6b 37 46 44 74 46 45 7a 6b 6d 4c 6d 73 3d } //1 RscLhYiIj4cZCxBLxg2BAY0GnQPPQk7FDtFEzkmLms=
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=14
 
}