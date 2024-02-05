
rule Backdoor_BAT_Bladabindi_ALE_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.ALE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 0a 00 "
		
	strings :
		$a_00_0 = {08 17 d6 0c 08 1a fe 02 0d 09 2c 02 de 5d 00 00 14 0b 08 b5 1f 64 28 28 00 00 0a 13 05 12 05 1f 64 12 01 1f 64 28 0d 00 00 06 16 fe 01 13 04 11 04 2c 02 2b ca } //03 00 
		$a_80_1 = {4e 6f 2d 4c 6f 76 65 } //No-Love  03 00 
		$a_80_2 = {63 61 70 47 65 74 44 72 69 76 65 72 44 65 73 63 72 69 70 74 69 6f 6e 41 } //capGetDriverDescriptionA  03 00 
		$a_80_3 = {63 6d 64 2e 65 78 65 20 2f 63 20 70 69 6e 67 20 30 20 2d 6e 20 32 20 26 20 64 65 6c } //cmd.exe /c ping 0 -n 2 & del  03 00 
		$a_80_4 = {4d 6f 65 31 } //Moe1  00 00 
	condition:
		any of ($a_*)
 
}