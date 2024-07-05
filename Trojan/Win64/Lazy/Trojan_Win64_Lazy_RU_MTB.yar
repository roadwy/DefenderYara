
rule Trojan_Win64_Lazy_RU_MTB{
	meta:
		description = "Trojan:Win64/Lazy.RU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 0f af f8 49 8b c2 48 f7 e7 48 c1 ea 07 48 69 c2 90 01 04 48 2b f8 41 8a c8 80 e1 07 c0 e1 03 48 0f be 95 90 01 04 48 d3 fa 40 32 fa 49 8b c2 49 f7 e1 48 c1 ea 07 48 69 c2 90 01 04 49 8b c9 48 2b c8 40 32 f9 42 30 bc 05 90 01 04 4d 03 c3 4c 03 cb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}