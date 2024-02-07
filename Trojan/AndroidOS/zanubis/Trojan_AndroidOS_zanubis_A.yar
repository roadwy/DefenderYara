
rule Trojan_AndroidOS_zanubis_A{
	meta:
		description = "Trojan:AndroidOS/zanubis.A,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {67 65 74 41 63 63 65 73 69 62 69 6c 69 64 61 64 56 69 73 74 61 45 73 74 61 64 6f } //02 00  getAccesibilidadVistaEstado
		$a_01_1 = {66 75 6e 63 69 6f 6e 43 6f 6e 65 63 74 61 72 53 65 72 76 65 72 } //02 00  funcionConectarServer
		$a_01_2 = {67 65 74 42 6c 6f 71 75 65 61 72 54 65 6c 65 66 6f 6e 6f } //02 00  getBloquearTelefono
		$a_01_3 = {45 6c 69 6d 69 6e 61 72 4e 6f 74 69 66 69 63 61 63 69 6f 6e 65 73 } //00 00  EliminarNotificaciones
	condition:
		any of ($a_*)
 
}