
rule Trojan_Win64_StrelaStealer_MA_MTB{
	meta:
		description = "Trojan:Win64/StrelaStealer.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {41 89 c8 41 81 e8 90 01 04 41 81 c0 90 01 04 41 81 c0 90 01 04 41 89 c1 45 29 c1 41 89 c0 41 81 e8 90 01 04 45 01 c1 41 89 c0 45 29 c8 41 81 e8 90 01 04 41 81 e8 90 01 04 41 81 c0 90 01 04 41 81 e8 90 01 04 41 81 e8 90 01 04 41 81 c0 90 01 04 83 e8 01 41 01 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}