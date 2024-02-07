
rule Backdoor_BAT_Sanhotan_A{
	meta:
		description = "Backdoor:BAT/Sanhotan.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {51 00 55 00 49 00 45 00 4e 00 20 00 45 00 53 00 20 00 54 00 55 00 20 00 44 00 49 00 4f 00 53 00 } //01 00  QUIEN ES TU DIOS
		$a_01_1 = {21 00 55 00 50 00 44 00 49 00 52 00 2d 00 54 00 } //01 00  !UPDIR-T
		$a_01_2 = {58 00 41 00 54 00 3a 00 4e 00 49 00 43 00 4b 00 } //01 00  XAT:NICK
		$a_01_3 = {53 61 6e 75 46 6c 6f 6f 64 48 69 6c 6f } //01 00  SanuFloodHilo
		$a_01_4 = {73 61 6e 43 61 6d } //01 00  sanCam
		$a_01_5 = {43 6f 70 79 46 72 6f 6d 53 63 72 65 65 6e } //01 00  CopyFromScreen
		$a_01_6 = {53 00 41 00 4e 00 3a 00 } //01 00  SAN:
		$a_01_7 = {53 00 43 00 52 00 3a 00 } //01 00  SCR:
		$a_01_8 = {43 00 41 00 4d 00 3a 00 } //01 00  CAM:
		$a_01_9 = {58 00 41 00 4f 00 3a 00 } //01 00  XAO:
		$a_01_10 = {4f 00 49 00 52 00 3a 00 } //00 00  OIR:
		$a_00_11 = {5d 04 00 00 } //d1 0c 
	condition:
		any of ($a_*)
 
}