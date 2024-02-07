
rule Trojan_Win32_Dridex_R_MSR{
	meta:
		description = "Trojan:Win32/Dridex.R!MSR,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {46 3a 5c 65 77 68 6a 52 23 48 52 45 6a 72 65 6a 45 52 6a 65 72 5c 77 6a 52 45 6a 77 52 4a 52 4a 5c 54 65 78 74 2e 65 78 65 } //00 00  F:\ewhjR#HREjrejERjer\wjREjwRJRJ\Text.exe
	condition:
		any of ($a_*)
 
}