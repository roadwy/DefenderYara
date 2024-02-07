
rule Trojan_Win32_Infostealer_HBAI_MTB{
	meta:
		description = "Trojan:Win32/Infostealer.HBAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {53 6f 73 6f 70 6f 6e 61 7a 75 62 69 72 69 6e } //02 00  Sosoponazubirin
		$a_01_1 = {77 65 78 65 74 61 } //02 00  wexeta
		$a_01_2 = {6b 65 6c 65 74 6f 6c 61 7a 65 6b 65 6d 61 6d 61 72 } //02 00  keletolazekemamar
		$a_01_3 = {72 69 62 65 68 75 70 6f 76 61 63 61 76 61 6c 6f 74 65 70 65 6e 65 67 65 64 69 63 75 67 } //02 00  ribehupovacavalotepenegedicug
		$a_01_4 = {53 65 6e 6f 76 75 6c } //02 00  Senovul
		$a_80_5 = {43 49 44 41 46 49 43 55 44 55 52 4f 53 4f 54 41 52 4f 4d } //CIDAFICUDUROSOTAROM  00 00 
	condition:
		any of ($a_*)
 
}