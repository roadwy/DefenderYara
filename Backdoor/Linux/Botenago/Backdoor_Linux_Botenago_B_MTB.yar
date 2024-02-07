
rule Backdoor_Linux_Botenago_B_MTB{
	meta:
		description = "Backdoor:Linux/Botenago.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 74 65 6c 6e 65 74 4c 6f 61 64 44 72 6f 70 70 65 72 73 } //01 00  main.telnetLoadDroppers
		$a_01_1 = {6d 61 69 6e 2e 74 65 6c 6e 65 74 48 61 73 42 75 73 79 62 6f 78 } //01 00  main.telnetHasBusybox
		$a_01_2 = {6d 61 69 6e 2e 69 6e 66 65 63 74 46 75 6e 63 74 69 6f 6e 42 72 6f 61 64 63 6f 6d } //01 00  main.infectFunctionBroadcom
		$a_01_3 = {6d 61 69 6e 2e 69 6e 66 65 63 74 46 75 6e 63 74 69 6f 6e 47 70 6f 6e 46 69 62 65 72 } //01 00  main.infectFunctionGponFiber
		$a_01_4 = {6d 61 69 6e 2e 69 6e 66 65 63 74 46 75 6e 63 74 69 6f 6e 4d 61 67 69 63 } //00 00  main.infectFunctionMagic
	condition:
		any of ($a_*)
 
}