
rule Trojan_Win64_Lazy_RW_MTB{
	meta:
		description = "Trojan:Win64/Lazy.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 00 41 b8 81 00 00 00 89 c2 4c 89 c1 41 89 c0 41 80 e0 0f c0 ea 04 45 8d 48 30 45 8d 58 37 41 80 f8 0a 45 0f b6 c1 45 0f b6 cb 45 0f 42 c8 44 88 4c 0c 26 } //00 00 
	condition:
		any of ($a_*)
 
}