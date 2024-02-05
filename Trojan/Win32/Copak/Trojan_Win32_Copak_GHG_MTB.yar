
rule Trojan_Win32_Copak_GHG_MTB{
	meta:
		description = "Trojan:Win32/Copak.GHG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {01 ea 31 3b 81 c0 90 01 04 81 c3 90 01 04 40 39 cb 75 e8 c3 c3 81 e9 90 01 04 81 ea 90 01 04 39 ff 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}