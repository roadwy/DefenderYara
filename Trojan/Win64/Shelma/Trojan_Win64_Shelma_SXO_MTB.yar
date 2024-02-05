
rule Trojan_Win64_Shelma_SXO_MTB{
	meta:
		description = "Trojan:Win64/Shelma.SXO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {88 45 b2 b8 63 00 00 00 88 45 b3 b8 6f 00 00 00 88 45 b4 b8 64 00 00 00 88 45 b5 b8 65 00 00 00 88 45 b6 b8 66 00 00 00 88 45 b7 b8 6f 00 00 00 88 45 b8 b8 78 00 00 00 88 45 b9 b8 2e 00 00 00 88 45 ba b8 74 00 00 00 88 45 bb b8 61 00 00 00 88 45 bc b8 6f 00 00 00 88 45 bd b8 62 00 00 00 88 45 be b8 61 00 00 00 88 45 bf b8 6f 00 00 00 88 45 c0 b8 2e 00 00 00 88 45 c1 b8 63 00 00 00 88 45 c2 b8 6f 00 00 00 88 45 c3 b8 6d 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}