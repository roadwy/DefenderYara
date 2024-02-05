
rule Trojan_Win64_Gamaredon_psyF_MTB{
	meta:
		description = "Trojan:Win64/Gamaredon.psyF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_03_0 = {48 c7 c1 01 00 00 80 e8 90 01 03 ff 4c 8d 05 ff 0c 00 00 48 8d 15 00 0d 00 00 48 c7 c1 01 00 00 80 e8 cc fd ff ff 4c 8d 8c 24 e0 00 00 00 4c 8d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}