
rule TrojanSpy_Win32_Bancos_AGP{
	meta:
		description = "TrojanSpy:Win32/Bancos.AGP,SIGNATURE_TYPE_PEHSTR,6f 00 6f 00 05 00 00 64 00 "
		
	strings :
		$a_01_0 = {66 6f 72 6d 5f 6a 5f 74 61 6e 63 6f 64 65 } //0a 00  form_j_tancode
		$a_01_1 = {6f 6e 6d 6f 75 73 65 6d 6f 76 65 3d 22 73 74 61 74 75 73 3d 27 42 61 6e 6b 6c 69 6e 65 27 22 } //0a 00  onmousemove="status='Bankline'"
		$a_01_2 = {3c 44 49 56 20 69 64 3d 48 4f 6c 61 74 65 73 71 3e 3c 54 41 42 4c 45 } //01 00  <DIV id=HOlatesq><TABLE
		$a_01_3 = {74 78 74 53 65 6e 68 61 } //01 00  txtSenha
		$a_01_4 = {46 72 6d 42 44 44 65 62 69 74 6f } //00 00  FrmBDDebito
	condition:
		any of ($a_*)
 
}