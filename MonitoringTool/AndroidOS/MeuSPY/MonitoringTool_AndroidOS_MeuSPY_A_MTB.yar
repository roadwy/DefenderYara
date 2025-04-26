
rule MonitoringTool_AndroidOS_MeuSPY_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/MeuSPY.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {52 65 63 65 69 76 65 72 54 65 6c 61 } //1 ReceiverTela
		$a_01_1 = {50 72 6f 63 65 73 73 61 72 56 69 64 65 6f 4f 66 66 } //1 ProcessarVideoOff
		$a_01_2 = {4c 56 69 64 65 6f 41 63 74 69 76 69 74 79 } //1 LVideoActivity
		$a_01_3 = {47 72 61 76 61 72 43 68 61 6d 61 64 61 } //1 GravarChamada
		$a_01_4 = {43 61 6d 65 72 61 46 69 6e 61 6c 69 7a 61 } //1 CameraFinaliza
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule MonitoringTool_AndroidOS_MeuSPY_A_MTB_2{
	meta:
		description = "MonitoringTool:AndroidOS/MeuSPY.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_01_0 = {4d 65 75 53 50 59 } //5 MeuSPY
		$a_01_1 = {41 75 64 69 6f 52 65 63 6f 72 64 65 72 43 61 6c 6c } //1 AudioRecorderCall
		$a_01_2 = {73 6d 73 2e 74 78 74 } //1 sms.txt
		$a_01_3 = {74 65 6c 65 66 6f 6e 65 2e 70 68 70 3f 69 64 3d } //1 telefone.php?id=
		$a_01_4 = {75 70 6c 6f 61 64 76 69 64 65 6f 73 6f 66 66 2e 70 68 70 } //1 uploadvideosoff.php
		$a_01_5 = {75 70 6c 6f 61 64 63 6f 6e 74 61 74 6f 2e 70 68 70 } //1 uploadcontato.php
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=9
 
}