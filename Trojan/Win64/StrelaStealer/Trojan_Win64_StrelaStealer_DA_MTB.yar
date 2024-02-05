
rule Trojan_Win64_StrelaStealer_DA_MTB{
	meta:
		description = "Trojan:Win64/StrelaStealer.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 89 c8 e8 90 01 04 48 29 c4 48 89 e0 48 8b 8d 90 01 04 48 89 85 90 01 04 48 89 c8 e8 90 01 04 48 29 c4 48 89 e0 48 8b 8d 90 01 04 48 89 85 90 01 04 48 89 c8 e8 90 01 04 48 29 c4 48 89 e0 48 8b 8d 90 01 04 48 89 85 90 01 04 48 89 c8 e8 90 01 04 48 29 c4 48 89 e0 48 8b 8d 90 00 } //01 00 
		$a_03_1 = {48 89 c1 48 81 c1 01 00 00 00 48 89 8d 90 01 04 8a 10 48 8b 85 90 01 04 48 89 c1 48 81 c1 01 00 00 00 48 89 8d 90 01 04 88 10 e9 90 09 07 00 48 8b 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}