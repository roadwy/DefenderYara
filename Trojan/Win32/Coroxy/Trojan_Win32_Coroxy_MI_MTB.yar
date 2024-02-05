
rule Trojan_Win32_Coroxy_MI_MTB{
	meta:
		description = "Trojan:Win32/Coroxy.MI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {40 99 f7 be 90 01 04 89 96 90 01 04 ba 90 01 04 8b ae 90 01 04 8b 45 90 01 01 2d 90 01 04 89 03 8b 9e 90 01 04 69 43 90 01 05 3b c2 74 90 01 01 8b be 90 01 04 8b 4e 90 01 01 81 c7 90 01 04 0f 1f 40 90 01 01 33 cf 42 89 4e 90 01 01 69 43 90 01 05 3b d0 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}