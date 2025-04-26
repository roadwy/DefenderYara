
rule Trojan_BAT_Zemsil_SS_MTB{
	meta:
		description = "Trojan:BAT/Zemsil.SS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {57 69 6e 5f 46 6f 72 6d 73 5f 43 6f 6c 6c 61 62 6f 72 61 74 69 6f 6e 2e 46 72 6d 50 6f 63 65 74 6e 61 2e 72 65 73 6f 75 72 63 65 73 } //2 Win_Forms_Collaboration.FrmPocetna.resources
		$a_01_1 = {24 34 63 32 34 63 66 33 66 2d 39 38 65 38 2d 34 66 36 33 2d 62 36 34 64 2d 65 30 38 63 66 37 39 33 63 35 39 30 } //2 $4c24cf3f-98e8-4f63-b64d-e08cf793c590
		$a_01_2 = {56 69 73 75 61 6c 20 4e 2d 51 75 65 65 6e 73 20 53 6f 6c 76 65 72 } //2 Visual N-Queens Solver
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}