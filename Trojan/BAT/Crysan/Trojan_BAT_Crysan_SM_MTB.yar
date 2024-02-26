
rule Trojan_BAT_Crysan_SM_MTB{
	meta:
		description = "Trojan:BAT/Crysan.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {07 08 07 08 91 20 81 02 00 00 59 d2 9c 00 08 17 58 0c 08 07 8e 69 fe 04 0d 09 2d e3 } //02 00 
		$a_01_1 = {53 69 73 74 65 6d 61 41 73 69 73 74 65 6e 63 69 61 73 2e 4c 6f 67 69 63 61 } //00 00  SistemaAsistencias.Logica
	condition:
		any of ($a_*)
 
}