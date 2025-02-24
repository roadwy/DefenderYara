
rule Trojan_Win64_KillAV_BSA_MTB{
	meta:
		description = "Trojan:Win64/KillAV.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 14 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 65 61 6c 42 6c 69 6e 64 69 6e 67 45 44 52 } //20 RealBlindingEDR
		$a_01_1 = {50 65 72 6d 61 6e 65 6e 74 6c 79 20 64 65 6c 65 74 65 20 41 56 2f 45 44 52 } //5 Permanently delete AV/EDR
		$a_01_2 = {64 72 69 76 65 72 5f 70 61 74 68 } //5 driver_path
		$a_01_3 = {52 65 61 6c 42 6c 69 6e 64 69 6e 67 45 44 52 2e 65 78 65 } //5 RealBlindingEDR.exe
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5) >=20
 
}