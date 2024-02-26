
rule Trojan_Win32_Zenpak_GPG_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_01_0 = {d0 8a 0c 0a 32 0c 1f 8b 5d e8 8b 55 d0 88 0c 13 c7 05 } //00 00 
	condition:
		any of ($a_*)
 
}