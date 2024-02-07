
rule MonitoringTool_AndroidOS_Anfur_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Anfur.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 72 2e 63 6f 6d 2e 6d 61 63 65 64 61 2e 61 6e 64 72 6f 69 64 2e 61 6e 74 69 66 75 72 74 6f 77 } //01 00  br.com.maceda.android.antifurtow
		$a_01_1 = {65 6e 76 69 6f 75 5f 6c 6f 63 61 6c 69 7a 61 63 61 6f 5f 67 70 73 } //01 00  enviou_localizacao_gps
		$a_01_2 = {65 6e 76 69 6f 75 5f 6c 6f 63 61 6c 69 7a 61 63 61 6f 5f 72 65 64 65 } //01 00  enviou_localizacao_rede
		$a_01_3 = {44 65 73 69 6e 73 74 61 6c 61 72 41 63 74 69 76 69 74 79 } //01 00  DesinstalarActivity
		$a_01_4 = {6a 6f 73 69 61 73 6d 61 63 65 64 61 40 67 6d 61 69 6c 2e 63 6f 6d } //01 00  josiasmaceda@gmail.com
		$a_01_5 = {61 74 75 61 6c 69 7a 61 72 45 6d 61 69 6c 4e 6f 53 65 72 76 69 64 6f 72 } //01 00  atualizarEmailNoServidor
		$a_01_6 = {6e 61 6f 53 75 70 6f 72 74 61 41 74 69 76 61 63 61 6f 47 50 53 } //00 00  naoSuportaAtivacaoGPS
	condition:
		any of ($a_*)
 
}