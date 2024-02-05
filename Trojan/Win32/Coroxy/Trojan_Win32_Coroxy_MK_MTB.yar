
rule Trojan_Win32_Coroxy_MK_MTB{
	meta:
		description = "Trojan:Win32/Coroxy.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {40 99 f7 be 90 01 04 89 96 90 01 04 8b 56 90 01 01 8b ae 90 01 04 81 c2 90 01 04 89 96 90 01 04 69 45 90 01 05 3b c7 74 90 01 01 8b 5e 90 01 01 8b 8e 90 01 04 8b 43 90 01 01 47 05 90 01 04 33 c8 89 8e 90 01 04 69 45 90 01 05 3b f8 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}