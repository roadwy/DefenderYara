
rule Trojan_BAT_LummaStealer_SK_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {03 50 06 8f 1c 00 00 01 25 71 1c 00 00 01 20 ae 00 00 00 58 d2 81 1c 00 00 01 03 50 06 8f 1c 00 00 01 25 71 1c 00 00 01 20 af 00 00 00 59 d2 81 1c 00 00 01 03 50 06 8f 1c 00 00 01 25 71 1c 00 00 01 20 e8 00 00 00 58 d2 81 1c 00 00 01 dd 03 00 00 00 } //02 00 
		$a_81_1 = {42 6c 69 6e 73 73 6f 6e } //00 00  Blinsson
	condition:
		any of ($a_*)
 
}