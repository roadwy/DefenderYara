
rule Trojan_Win64_StrelaStealer_PQA_MTB{
	meta:
		description = "Trojan:Win64/StrelaStealer.PQA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {44 89 cf 83 f7 90 01 01 81 e7 90 01 04 41 89 df 41 81 f7 90 01 04 45 21 f9 44 09 cf 41 83 f3 90 01 01 83 f7 90 01 01 41 89 d9 41 81 f1 90 01 04 41 09 fb 41 81 c9 90 01 04 41 83 f3 90 01 01 45 21 cb 45 89 f1 45 21 d9 45 31 de 45 09 f1 90 00 } //01 00 
		$a_03_1 = {45 31 d4 41 09 f0 41 83 f0 90 01 01 81 cb 90 01 04 41 21 d8 45 09 c4 45 89 e8 41 83 f0 90 01 01 41 81 e0 90 01 04 41 89 fa 41 81 f2 90 01 04 45 21 d5 44 89 e6 83 f6 ff 81 e6 90 01 04 45 21 d4 45 09 e8 44 09 e6 41 31 f0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}