
rule TrojanSpy_Win32_Bancos_AIS{
	meta:
		description = "TrojanSpy:Win32/Bancos.AIS,SIGNATURE_TYPE_PEHSTR,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 65 6e 68 61 63 61 72 74 61 6f } //01 00  senhacartao
		$a_01_1 = {75 00 70 00 64 00 61 00 74 00 65 00 20 00 63 00 6f 00 6e 00 74 00 5f 00 6d 00 6f 00 74 00 6f 00 5f 00 76 00 65 00 72 00 6d 00 65 00 6c 00 68 00 61 00 } //01 00  update cont_moto_vermelha
		$a_01_2 = {6f 00 6e 00 4d 00 6f 00 75 00 73 00 65 00 4d 00 6f 00 76 00 65 00 3d 00 22 00 73 00 74 00 61 00 74 00 75 00 73 00 3d 00 22 00 42 00 61 00 6e 00 6b 00 6c 00 69 00 6e 00 65 00 } //01 00  onMouseMove="status="Bankline
		$a_01_3 = {3c 00 44 00 49 00 56 00 20 00 69 00 64 00 3d 00 48 00 4f 00 6c 00 61 00 74 00 65 00 73 00 71 00 3e 00 } //01 00  <DIV id=HOlatesq>
		$a_01_4 = {74 00 79 00 70 00 65 00 3d 00 68 00 69 00 64 00 64 00 65 00 6e 00 20 00 6e 00 61 00 6d 00 65 00 3d 00 4d 00 45 00 52 00 43 00 48 00 41 00 4e 00 54 00 49 00 44 00 } //00 00  type=hidden name=MERCHANTID
	condition:
		any of ($a_*)
 
}