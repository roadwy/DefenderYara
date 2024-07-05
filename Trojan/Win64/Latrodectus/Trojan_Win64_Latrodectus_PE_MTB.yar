
rule Trojan_Win64_Latrodectus_PE_MTB{
	meta:
		description = "Trojan:Win64/Latrodectus.PE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 63 c8 49 8b c4 48 f7 e1 48 c1 ea 04 48 6b c2 11 48 2b c8 49 2b cb 0f b6 44 0c 90 01 01 42 32 44 0b 90 01 01 41 88 41 90 01 01 41 8d 42 90 01 01 48 63 c8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}