
rule Trojan_Win64_Rozena_PC_MTB{
	meta:
		description = "Trojan:Win64/Rozena.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 0f af c2 48 c1 e8 90 01 01 89 c2 c1 ea 90 01 01 89 d0 c1 e0 90 01 01 01 d0 c1 e0 90 01 01 29 c1 89 ca 89 d2 48 90 01 06 0f b6 04 02 89 c1 8b 45 90 01 01 48 63 d0 48 8b 45 90 01 01 48 01 d0 44 89 c2 31 ca 88 10 83 45 fc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}