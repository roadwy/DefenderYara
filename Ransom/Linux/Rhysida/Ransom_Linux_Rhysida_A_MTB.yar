
rule Ransom_Linux_Rhysida_A_MTB{
	meta:
		description = "Ransom:Linux/Rhysida.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 68 79 73 69 64 61 2d 30 2e 31 } //01 00  Rhysida-0.1
		$a_01_1 = {65 73 78 63 6c 69 20 73 79 73 74 65 6d 20 77 65 6c 63 6f 6d 65 6d 73 67 20 73 65 74 20 2d 6d } //01 00  esxcli system welcomemsg set -m
		$a_01_2 = {43 72 69 74 69 63 61 6c 42 72 65 61 63 68 44 65 74 65 63 74 65 64 } //01 00  CriticalBreachDetected
		$a_01_3 = {2f 62 69 6e 2f 72 6d 20 2d 66 } //01 00  /bin/rm -f
		$a_03_4 = {72 68 79 73 69 64 61 90 02 58 2e 6f 6e 69 6f 6e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}