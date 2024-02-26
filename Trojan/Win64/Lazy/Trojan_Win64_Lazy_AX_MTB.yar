
rule Trojan_Win64_Lazy_AX_MTB{
	meta:
		description = "Trojan:Win64/Lazy.AX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {45 33 c9 44 0f b7 84 24 10 02 00 00 48 8b 94 24 08 02 00 00 48 8b 8c 24 c8 00 00 00 ff 15 90 01 04 48 89 84 24 d0 00 00 00 48 83 bc 24 d0 00 00 00 00 75 90 00 } //01 00 
		$a_81_1 = {70 61 79 6c 6f 61 64 2e 62 69 6e } //00 00  payload.bin
	condition:
		any of ($a_*)
 
}