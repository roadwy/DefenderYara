
rule VirTool_Win32_Wraith_A_MTB{
	meta:
		description = "VirTool:Win32/Wraith.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {28 2a 57 72 61 69 74 68 29 2e 49 6e 69 74 } //01 00  (*Wraith).Init
		$a_01_1 = {28 2a 57 72 61 69 74 68 29 2e 50 75 73 68 54 78 } //01 00  (*Wraith).PushTx
		$a_01_2 = {28 2a 57 72 61 69 74 68 29 2e 50 75 73 68 52 78 } //01 00  (*Wraith).PushRx
		$a_01_3 = {28 2a 57 72 61 69 74 68 29 2e 52 75 6e } //01 00  (*Wraith).Run
		$a_01_4 = {28 2a 54 78 48 61 6e 64 6c 65 72 29 2e 49 6e 69 74 } //01 00  (*TxHandler).Init
		$a_01_5 = {28 2a 52 78 48 61 6e 64 6c 65 72 29 2e 49 6e 69 74 } //01 00  (*RxHandler).Init
		$a_01_6 = {28 2a 57 72 61 69 74 68 29 2e 53 68 75 74 64 6f 77 6e } //00 00  (*Wraith).Shutdown
	condition:
		any of ($a_*)
 
}