
rule Ransom_MSIL_ShinoLocker_KS_MTB{
	meta:
		description = "Ransom:MSIL/ShinoLocker.KS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 0a 00 "
		
	strings :
		$a_00_0 = {06 72 a0 61 00 70 28 51 00 00 0a 72 a0 61 00 70 28 52 00 00 0a 6b 5a 22 00 00 80 3f 58 28 53 00 00 0a 6c 28 54 00 00 0a b7 17 28 55 00 00 0a 28 3c 00 00 0a 0a 08 17 d6 0c 08 07 31 c3 } //03 00 
		$a_80_1 = {2e 73 68 69 6e 6f } //.shino  03 00 
		$a_80_2 = {67 65 74 5f 53 74 61 72 74 49 6e 66 6f } //get_StartInfo  03 00 
		$a_80_3 = {67 65 74 5f 45 78 65 63 75 74 61 62 6c 65 50 61 74 68 } //get_ExecutablePath  03 00 
		$a_80_4 = {53 68 69 6e 6f 4c 6f 63 6b 65 72 } //ShinoLocker  00 00 
	condition:
		any of ($a_*)
 
}