
rule Trojan_Win64_Dridex_ALK_MTB{
	meta:
		description = "Trojan:Win64/Dridex.ALK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_80_0 = {62 65 6e 63 68 6d 61 72 6b 73 2c 66 72 6f 6d 48 76 6f 74 68 65 72 74 68 65 6d 2e 32 39 38 39 2e 37 35 25 52 65 73 69 67 2c 74 68 65 } //benchmarks,fromHvotherthem.2989.75%Resig,the  03 00 
		$a_80_1 = {74 34 32 2e 30 2e 32 33 31 31 2e 34 6d 61 64 65 72 43 68 72 6f 6d 65 79 61 6e 6b 65 65 54 6e 74 68 65 } //t42.0.2311.4maderChromeyankeeTnthe  03 00 
		$a_80_2 = {73 74 61 72 74 69 6e 67 71 61 6e 64 76 69 73 69 74 65 64 47 5a 39 38 37 36 35 34 35 35 35 35 35 35 34 } //startingqandvisitedGZ9876545555554  03 00 
		$a_80_3 = {47 65 74 43 6c 75 73 74 65 72 52 65 73 6f 75 72 63 65 4e 65 74 77 6f 72 6b 4e 61 6d 65 } //GetClusterResourceNetworkName  03 00 
		$a_80_4 = {47 76 6f 61 6e 64 69 6e 32 30 31 38 2c 59 62 6f 78 6a 61 63 6b 69 65 59 } //Gvoandin2018,YboxjackieY  03 00 
		$a_80_5 = {4c 6f 6f 6b 75 70 41 63 63 6f 75 6e 74 53 69 64 41 } //LookupAccountSidA  03 00 
		$a_80_6 = {46 69 6e 64 46 69 72 73 74 46 72 65 65 41 63 65 } //FindFirstFreeAce  00 00 
	condition:
		any of ($a_*)
 
}