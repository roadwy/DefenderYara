
rule Backdoor_Win64_Repezor_B{
	meta:
		description = "Backdoor:Win64/Repezor.B,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {30 3a 5c 73 74 6f 72 61 67 65 5c 63 6f 6e 66 69 67 00 } //01 00  㨰獜潴慲敧捜湯楦g
		$a_01_1 = {62 63 5f 70 6c 75 67 00 } //01 00  换灟畬g
		$a_03_2 = {3d 01 05 00 00 7c 90 01 01 3d 02 05 00 00 7e 90 01 01 3d 00 06 00 00 74 90 01 01 3d 01 06 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}