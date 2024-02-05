
rule Trojan_Win32_SmokeLoader_AJ_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.AJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {ac a8 ac ac 49 f5 ab ee 34 48 fd 00 47 47 47 ac 42 e4 5d ac b2 88 af } //00 00 
	condition:
		any of ($a_*)
 
}