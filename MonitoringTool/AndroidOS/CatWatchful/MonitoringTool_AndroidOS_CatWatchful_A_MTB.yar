
rule MonitoringTool_AndroidOS_CatWatchful_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/CatWatchful.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {6f 62 74 65 6e 65 72 4e 6f 6d 62 72 65 43 6f 6e 74 61 63 74 6f } //1 obtenerNombreContacto
		$a_00_1 = {65 6e 76 69 61 72 48 69 73 74 6f 72 69 61 6c 4c 6c 61 6d 61 64 61 73 } //1 enviarHistorialLlamadas
		$a_00_2 = {6f 62 74 65 6e 65 72 55 6c 74 69 6d 6f 73 53 6d 73 } //1 obtenerUltimosSms
		$a_00_3 = {77 6f 73 63 2f 70 6c 61 79 2f 64 6f 6d 69 6e 69 6f } //1 wosc/play/dominio
		$a_00_4 = {47 72 61 62 61 63 69 6f 6e 20 65 6e 20 63 75 72 73 6f } //1 Grabacion en curso
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}