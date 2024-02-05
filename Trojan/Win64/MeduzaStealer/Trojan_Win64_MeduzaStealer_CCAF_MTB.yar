
rule Trojan_Win64_MeduzaStealer_CCAF_MTB{
	meta:
		description = "Trojan:Win64/MeduzaStealer.CCAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {f7 e3 d1 ea 8d 0c 52 3b d9 48 8d 15 90 01 04 48 8b cf 74 90 00 } //01 00 
		$a_01_1 = {4d 65 64 75 5a 5a 5a 61 } //00 00 
	condition:
		any of ($a_*)
 
}