
rule Trojan_Win64_Shelma_AT_MTB{
	meta:
		description = "Trojan:Win64/Shelma.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {ff c2 48 63 c2 48 8d 4c 24 20 48 03 c8 0f b6 01 41 88 04 38 44 88 09 41 0f b6 0c 38 49 03 c9 0f b6 c1 0f b6 4c 04 20 41 30 0e 49 ff c6 49 83 ea 01 75 } //00 00 
	condition:
		any of ($a_*)
 
}