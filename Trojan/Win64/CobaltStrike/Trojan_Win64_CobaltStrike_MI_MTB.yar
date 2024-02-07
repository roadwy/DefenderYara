
rule Trojan_Win64_CobaltStrike_MI_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 72 6f 6a 65 63 74 73 5c 65 76 61 73 69 6f 6e 43 5f 67 6f 5c 77 6f 72 6b 69 6e 67 53 70 61 63 65 } //01 00  Projects\evasionC_go\workingSpace
		$a_00_1 = {5f 73 65 68 5f 66 69 6c 74 65 72 5f 64 6c 6c } //00 00  _seh_filter_dll
	condition:
		any of ($a_*)
 
}