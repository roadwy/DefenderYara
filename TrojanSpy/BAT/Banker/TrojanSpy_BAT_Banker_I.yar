
rule TrojanSpy_BAT_Banker_I{
	meta:
		description = "TrojanSpy:BAT/Banker.I,SIGNATURE_TYPE_PEHSTR_EXT,ffffff87 00 ffffff82 00 0a 00 00 32 00 "
		
	strings :
		$a_01_0 = {6d 00 61 00 69 00 6e 00 73 00 65 00 6e 00 64 00 65 00 72 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00 } //32 00  mainsender@gmail.com
		$a_01_1 = {79 00 65 00 73 00 67 00 61 00 6d 00 65 00 32 00 30 00 30 00 35 00 40 00 68 00 6f 00 74 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 2e 00 75 00 6b 00 } //0a 00  yesgame2005@hotmail.co.uk
		$a_01_2 = {62 00 61 00 63 00 6b 00 75 00 70 00 73 00 65 00 6e 00 64 00 65 00 72 00 31 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00 } //0a 00  backupsender1@gmail.com
		$a_01_3 = {66 6f 72 6d 43 61 70 69 74 61 6c 6f 6e 65 00 43 61 72 64 64 65 74 61 69 6c 73 } //05 00  潦浲慃楰慴潬敮䌀牡摤瑥楡獬
		$a_01_4 = {46 6f 72 6d 42 61 72 63 6c 61 79 63 61 72 64 5f 4c 6f 61 64 } //05 00  FormBarclaycard_Load
		$a_01_5 = {42 61 6e 6b 4f 66 53 63 6f 74 5f 4c 6f 61 64 } //05 00  BankOfScot_Load
		$a_01_6 = {67 65 74 5f 49 6e 74 65 6c 6c 69 67 65 6e 74 46 69 6e 61 6e 63 65 4d 65 6d 6f } //05 00  get_IntelligentFinanceMemo
		$a_01_7 = {6d 5f 43 61 72 64 64 65 74 61 69 6c 73 } //05 00  m_Carddetails
		$a_01_8 = {7a 00 71 00 72 00 78 00 7a 00 78 00 6b 00 62 00 69 00 76 00 73 00 69 00 6f 00 6f 00 6c 00 72 00 } //05 00  zqrxzxkbivsioolr
		$a_01_9 = {70 00 65 00 72 00 73 00 6f 00 6e 00 61 00 6c 00 2f 00 6c 00 6f 00 67 00 6f 00 6e 00 2f 00 6c 00 6f 00 67 00 69 00 6e 00 2e 00 6a 00 73 00 70 00 } //00 00  personal/logon/login.jsp
	condition:
		any of ($a_*)
 
}