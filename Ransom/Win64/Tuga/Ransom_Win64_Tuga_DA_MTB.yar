
rule Ransom_Win64_Tuga_DA_MTB{
	meta:
		description = "Ransom:Win64/Tuga.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 61 6e 73 6f 6d 54 75 67 61 2d 6d 61 73 74 65 72 } //01 00  RansomTuga-master
		$a_01_1 = {59 6f 75 27 76 65 20 62 65 65 6e 20 68 61 63 6b 65 64 } //01 00  You've been hacked
		$a_01_2 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //00 00  CreateToolhelp32Snapshot
	condition:
		any of ($a_*)
 
}