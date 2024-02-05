
rule HackTool_Win64_Mimikatz_gen_IB{
	meta:
		description = "HackTool:Win64/Mimikatz.gen!IB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_80_0 = {69 63 65 5f 74 79 70 65 73 2e 73 65 63 72 65 74 73 2e 6d 69 6d 69 6b 61 74 7a 2e 4d 69 6d 69 6b 61 74 7a 52 65 73 75 6c 74 } //ice_types.secrets.mimikatz.MimikatzResult  01 00 
		$a_80_1 = {4d 69 6d 69 41 72 67 73 } //MimiArgs  01 00 
		$a_80_2 = {6d 69 6d 69 64 72 76 2e 73 79 73 } //mimidrv.sys  01 00 
		$a_80_3 = {76 61 75 6c 74 63 6c 69 } //vaultcli  01 00 
		$a_80_4 = {43 6c 65 61 72 54 68 72 65 61 64 4c 6f 63 61 6c 46 69 62 65 72 43 61 6c 6c 62 61 63 6b 73 } //ClearThreadLocalFiberCallbacks  01 00 
		$a_80_5 = {69 63 65 6b 61 74 7a 5f 72 75 6e } //icekatz_run  00 00 
	condition:
		any of ($a_*)
 
}