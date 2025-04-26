
rule TrojanSpy_BAT_Stealer_SQ_MTB{
	meta:
		description = "TrojanSpy:BAT/Stealer.SQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_81_0 = {54 69 63 5f 54 61 63 5f 54 6f 65 2e 54 69 63 54 61 63 54 6f 65 50 72 65 76 69 65 77 2e 72 65 73 6f 75 72 63 65 73 } //2 Tic_Tac_Toe.TicTacToePreview.resources
		$a_81_1 = {24 35 33 30 32 66 35 61 37 2d 37 31 30 30 2d 34 66 37 61 2d 61 32 36 62 2d 37 62 61 31 61 66 38 36 32 33 64 38 } //2 $5302f5a7-7100-4f7a-a26b-7ba1af8623d8
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}