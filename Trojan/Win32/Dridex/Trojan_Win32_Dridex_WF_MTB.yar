
rule Trojan_Win32_Dridex_WF_MTB{
	meta:
		description = "Trojan:Win32/Dridex.WF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 03 00 "
		
	strings :
		$a_80_0 = {44 54 54 59 55 4e 4d 50 2e 70 64 62 } //DTTYUNMP.pdb  03 00 
		$a_80_1 = {4e 64 72 43 6c 65 61 72 4f 75 74 50 61 72 61 6d 65 74 65 72 73 } //NdrClearOutParameters  03 00 
		$a_80_2 = {72 61 69 73 69 6e 67 6e 35 38 37 } //raisingn587  03 00 
		$a_80_3 = {61 69 6e 63 6c 75 64 69 6e 67 31 70 } //aincluding1p  03 00 
		$a_80_4 = {53 65 74 49 43 4d 4d 6f 64 65 } //SetICMMode  03 00 
		$a_80_5 = {52 50 43 52 54 34 2e 64 6c 6c } //RPCRT4.dll  00 00 
	condition:
		any of ($a_*)
 
}