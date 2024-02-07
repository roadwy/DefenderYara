
rule Trojan_BAT_AgentTesla_VIA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.VIA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {24 35 30 62 64 34 38 61 61 2d 35 65 36 37 2d 34 31 32 62 2d 62 33 37 64 2d 35 66 31 33 30 63 62 31 30 37 31 36 } //01 00  $50bd48aa-5e67-412b-b37d-5f130cb10716
		$a_81_1 = {50 61 43 6d 61 6e 2e 41 62 6f 75 74 42 6f 78 31 2e 72 65 73 6f 75 72 63 65 73 } //01 00  PaCman.AboutBox1.resources
		$a_81_2 = {50 61 43 6d 61 6e 2e 43 6f 6e 74 72 6f 6c 6c 65 72 5f 4d 61 69 6e 46 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //01 00  PaCman.Controller_MainForm.resources
		$a_81_3 = {50 61 43 6d 61 6e 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  PaCman.Properties.Resources.resources
		$a_81_4 = {50 61 43 6d 61 6e 2e 56 69 65 77 2e 72 65 73 6f 75 72 63 65 73 } //01 00  PaCman.View.resources
		$a_01_5 = {73 00 64 00 66 00 3b 00 2c 00 6b 00 6c 00 6d 00 76 00 67 00 64 00 6b 00 6c 00 73 00 6a 00 66 00 64 00 6f 00 69 00 73 00 61 00 6b 00 6c 00 75 00 66 00 68 00 6e 00 61 00 73 00 6b 00 69 00 64 00 75 00 6a 00 66 00 68 00 62 00 61 00 73 00 64 00 6a 00 6b 00 68 00 66 00 5f 00 32 00 } //01 00  sdf;,klmvgdklsjfdoisaklufhnaskidujfhbasdjkhf_2
		$a_81_6 = {67 65 74 5f 4d 4e 42 56 43 58 43 5a 42 47 59 48 } //00 00  get_MNBVCXCZBGYH
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_VIA_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.VIA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0f 00 00 01 00 "
		
	strings :
		$a_81_0 = {24 62 38 30 35 64 32 37 33 2d 35 35 61 33 2d 34 64 65 64 2d 61 63 34 33 2d 38 61 39 65 39 30 32 62 30 34 33 65 } //01 00  $b805d273-55a3-4ded-ac43-8a9e902b043e
		$a_81_1 = {4d 4e 42 56 43 58 43 5a 42 47 59 48 } //01 00  MNBVCXCZBGYH
		$a_81_2 = {46 61 63 74 6f 72 2e 46 61 63 74 6f 72 2e 72 65 73 6f 75 72 63 65 73 } //01 00  Factor.Factor.resources
		$a_81_3 = {41 72 72 61 6e 67 65 50 69 63 74 75 72 65 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //01 00  ArrangePicture.Form1.resources
		$a_81_4 = {49 54 6f 6b 65 6e 52 65 61 64 65 72 2e 66 72 6d 49 54 6f 6b 65 6e 52 65 61 64 65 72 2e 72 65 73 6f 75 72 63 65 73 } //01 00  ITokenReader.frmITokenReader.resources
		$a_81_5 = {49 54 6f 6b 65 6e 52 65 61 64 65 72 2e 66 72 6d 44 65 73 74 69 6e 6f 2e 72 65 73 6f 75 72 63 65 73 } //01 00  ITokenReader.frmDestino.resources
		$a_81_6 = {49 54 6f 6b 65 6e 52 65 61 64 65 72 2e 66 72 6d 50 65 73 73 6f 61 2e 72 65 73 6f 75 72 63 65 73 } //01 00  ITokenReader.frmPessoa.resources
		$a_81_7 = {49 54 6f 6b 65 6e 52 65 61 64 65 72 2e 66 72 6d 50 72 69 6e 63 69 70 61 6c 2e 72 65 73 6f 75 72 63 65 73 } //01 00  ITokenReader.frmPrincipal.resources
		$a_81_8 = {49 54 6f 6b 65 6e 52 65 61 64 65 72 2e 66 72 6d 53 6f 62 72 65 2e 72 65 73 6f 75 72 63 65 73 } //01 00  ITokenReader.frmSobre.resources
		$a_81_9 = {49 54 6f 6b 65 6e 52 65 61 64 65 72 2e 66 72 6d 54 72 61 6d 69 74 61 6e 64 6f 2e 72 65 73 6f 75 72 63 65 73 } //01 00  ITokenReader.frmTramitando.resources
		$a_81_10 = {56 65 68 69 63 6c 65 4d 61 6e 61 67 65 72 2e 4c 69 73 74 56 69 65 77 2e 72 65 73 6f 75 72 63 65 73 } //01 00  VehicleManager.ListView.resources
		$a_81_11 = {56 65 68 69 63 6c 65 4d 61 6e 61 67 65 72 2e 4d 61 69 6e 46 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //01 00  VehicleManager.MainForm.resources
		$a_81_12 = {49 54 6f 6b 65 6e 52 65 61 64 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  ITokenReader.Properties.Resources.resources
		$a_81_13 = {49 54 6f 6b 65 6e 52 65 61 64 65 72 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  ITokenReader.Resources.resources
		$a_81_14 = {56 65 68 69 63 6c 65 4d 61 6e 61 67 65 72 2e 54 79 70 65 43 6f 6e 74 72 6f 6c 2e 72 65 73 6f 75 72 63 65 73 } //00 00  VehicleManager.TypeControl.resources
	condition:
		any of ($a_*)
 
}