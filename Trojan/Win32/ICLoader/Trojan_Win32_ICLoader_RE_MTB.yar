
rule Trojan_Win32_ICLoader_RE_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {5d c3 8b c6 5e 5b 5d c3 90 90 90 90 90 90 90 90 90 90 90 90 90 55 8b ec 57 e9 } //00 00 
	condition:
		any of ($a_*)
 
}