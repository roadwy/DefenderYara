
rule Trojan_BAT_RedLineStealer_SD_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.SD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {4f 6e 6c 69 6e 65 4c 69 63 65 6e 73 69 6e 67 2e 64 6c 6c } //OnlineLicensing.dll  3
		$a_80_1 = {57 72 69 74 65 43 61 63 68 65 64 43 6c 69 65 6e 74 52 69 67 68 74 73 54 6f 6b 65 6e } //WriteCachedClientRightsToken  3
		$a_80_2 = {37 71 4f 74 65 78 73 72 62 61 52 71 6d 42 75 54 36 43 71 42 5a 67 3d 3d } //7qOtexsrbaRqmBuT6CqBZg==  3
		$a_80_3 = {69 39 53 75 36 67 68 4f 6b 4a 69 37 58 35 37 77 6a 75 4e 77 67 48 6b 51 4f 54 38 45 6f 43 76 50 31 33 38 6a 59 6f 2f 68 62 34 34 3d } //i9Su6ghOkJi7X57wjuNwgHkQOT8EoCvP138jYo/hb44=  3
		$a_80_4 = {74 65 6c 65 6d 65 74 72 79 4c 6f 67 67 65 72 } //telemetryLogger  3
		$a_80_5 = {4f 6e 6c 69 6e 65 4c 69 63 65 6e 73 69 6e 67 2e 70 64 62 } //OnlineLicensing.pdb  3
		$a_80_6 = {4e 65 72 64 62 61 6e 6b 2e 47 69 74 56 65 72 73 69 6f 6e 69 6e 67 2e 54 61 73 6b 73 } //Nerdbank.GitVersioning.Tasks  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}