
rule Trojan_Win32_LummaStealer_NLE_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.NLE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {47 75 61 72 64 72 61 69 6c 73 20 41 6c 6f 69 6e 20 43 6f 67 65 6e 74 } //2 Guardrails Aloin Cogent
		$a_01_1 = {53 69 67 6e 6f 72 20 53 68 65 72 65 65 66 73 20 4d 6f 73 73 67 72 6f 77 6e } //2 Signor Shereefs Mossgrown
		$a_01_2 = {4c 69 73 74 20 43 6f 6e 74 72 6f 6c 6c 65 72 20 53 65 74 75 70 } //2 List Controller Setup
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}