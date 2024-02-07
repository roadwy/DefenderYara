
rule Trojan_AndroidOS_PixStealer_A{
	meta:
		description = "Trojan:AndroidOS/PixStealer.A,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 05 00 00 05 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 67 73 65 72 76 69 63 65 2f 61 75 74 6f 62 6f 74 2f 41 63 65 73 73 69 62 69 6c 69 64 61 64 65 } //01 00  Lcom/gservice/autobot/Acessibilidade
		$a_00_1 = {46 72 61 6d 65 77 6f 72 6b 3a 3a 41 75 74 6f 42 6f 74 3a 3a 53 6f 63 6b 65 74 3a 3a 56 69 73 75 61 6c 69 7a 61 72 3a 3a 53 65 6e 43 6c 69 63 6b 65 64 } //01 00  Framework::AutoBot::Socket::Visualizar::SenClicked
		$a_00_2 = {76 61 6c 6f 72 } //01 00  valor
		$a_00_3 = {64 78 54 68 72 65 61 64 5f 50 72 6f 74 65 63 74 } //01 00  dxThread_Protect
		$a_00_4 = {3c 63 6d 64 3e } //00 00  <cmd>
	condition:
		any of ($a_*)
 
}