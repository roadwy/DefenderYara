
rule Trojan_BAT_SpyAgent_E_AMTB{
	meta:
		description = "Trojan:BAT/SpyAgent.E!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {6e 6f 6f 62 73 61 69 62 6f 74 52 41 54 2e 48 56 4e 43 2e 64 6c 6c } //noobsaibotRAT.HVNC.dll  1
		$a_80_1 = {41 67 65 6e 74 43 6f 72 65 2e 43 6f 72 65 2e 54 61 73 6b 50 72 6f 63 65 73 73 6f 72 2b 3c 45 78 65 63 75 74 65 53 74 65 61 6c 44 61 74 61 3e } //AgentCore.Core.TaskProcessor+<ExecuteStealData>  2
		$a_80_2 = {53 74 65 61 6c 65 72 43 6f 6f 72 64 69 6e 61 74 6f 72 5d 20 } //StealerCoordinator]   1
		$a_80_3 = {6e 6f 6f 62 73 61 69 62 6f 74 52 41 54 5f 53 74 65 61 6c 65 72 } //noobsaibotRAT_Stealer  2
		$a_80_4 = {42 72 6f 77 73 65 72 43 72 65 64 69 74 43 61 72 64 53 74 65 61 6c 65 72 } //BrowserCreditCardStealer  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*2+(#a_80_2  & 1)*1+(#a_80_3  & 1)*2+(#a_80_4  & 1)*1) >=5
 
}