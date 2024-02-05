
rule Trojan_Win32_Dridex_BAN_MTB{
	meta:
		description = "Trojan:Win32/Dridex.BAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_80_0 = {46 6e 6c 6f 64 65 72 54 72 52 70 70 65 65 } //FnloderTrRppee  03 00 
		$a_80_1 = {79 79 73 65 65 77 34 2e 70 64 62 } //yyseew4.pdb  03 00 
		$a_80_2 = {72 72 70 6f 6b 64 6d 67 6e 6e } //rrpokdmgnn  03 00 
		$a_80_3 = {74 45 66 72 65 65 4b 76 69 72 74 75 61 6c 77 68 69 63 68 43 68 72 6f 6d 65 } //tEfreeKvirtualwhichChrome  03 00 
		$a_80_4 = {52 65 67 4f 76 65 72 72 69 64 65 50 72 65 64 65 66 4b 65 79 } //RegOverridePredefKey  03 00 
		$a_80_5 = {6b 65 72 6e 65 6c 33 32 2e 53 6c 65 65 70 } //kernel32.Sleep  03 00 
		$a_80_6 = {63 68 6f 73 65 6e 39 46 70 61 72 74 } //chosen9Fpart  00 00 
	condition:
		any of ($a_*)
 
}