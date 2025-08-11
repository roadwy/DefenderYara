
rule MonitoringTool_AndroidOS_CatWatchful_C_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/CatWatchful.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,09 00 09 00 07 00 00 "
		
	strings :
		$a_01_0 = {4c 77 6f 73 63 2f 70 6c 61 79 2f 57 61 6b 65 55 70 } //2 Lwosc/play/WakeUp
		$a_01_1 = {4c 77 6f 73 63 2f 70 6c 61 79 2f 64 65 74 65 63 74 6f 72 65 73 2f 44 65 74 65 63 74 61 4e 6f 74 69 66 69 63 61 63 69 6f 6e 65 73 } //2 Lwosc/play/detectores/DetectaNotificaciones
		$a_01_2 = {4c 77 6f 73 63 2f 70 6c 61 79 2f 64 65 74 65 63 74 6f 72 65 73 2f 44 65 74 65 63 74 61 47 70 73 4f 6e 4f 66 66 } //2 Lwosc/play/detectores/DetectaGpsOnOff
		$a_01_3 = {4c 77 6f 73 63 2f 70 6c 61 79 2f 64 6f 6d 69 6e 69 6f } //2 Lwosc/play/dominio
		$a_01_4 = {67 75 61 72 64 61 72 4c 69 73 74 61 53 6d 73 } //1 guardarListaSms
		$a_01_5 = {75 6c 74 69 6d 6f 54 69 6d 65 53 74 61 6d 70 53 6d 73 } //1 ultimoTimeStampSms
		$a_01_6 = {67 65 74 55 73 72 50 61 73 73 77 6f 72 64 26 65 6d 61 69 6c 3d } //1 getUsrPassword&email=
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=9
 
}