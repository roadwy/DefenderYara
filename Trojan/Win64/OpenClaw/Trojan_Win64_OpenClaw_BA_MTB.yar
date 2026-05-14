
rule Trojan_Win64_OpenClaw_BA_MTB{
	meta:
		description = "Trojan:Win64/OpenClaw.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {54 72 61 64 65 20 41 49 20 4c 61 62 73 } //1 Trade AI Labs
		$a_81_1 = {54 72 61 64 65 41 49 2e 65 78 65 } //1 TradeAI.exe
		$a_81_2 = {41 49 20 61 6e 61 6c 79 73 69 73 20 61 6e 64 20 70 72 65 64 69 63 74 69 76 65 20 6d 6f 64 65 6c 69 6e 67 20 74 6f 6f 6c 6b 69 74 2e } //1 AI analysis and predictive modeling toolkit.
		$a_81_3 = {41 75 74 6f 6d 61 74 69 63 20 68 61 72 64 77 61 72 65 20 64 72 69 76 65 72 20 75 70 64 61 74 65 20 74 6f 6f 6c } //1 Automatic hardware driver update tool
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}