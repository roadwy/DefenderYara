
rule Trojan_BAT_Spynoon_AAPM_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.AAPM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {0d 09 08 1f 10 6f ?? 00 00 0a 6f ?? 00 00 0a 09 08 1f 10 6f ?? 00 00 0a 6f ?? 00 00 0a 09 6f ?? 00 00 0a 07 16 07 8e 69 6f ?? 00 00 0a 28 ?? 00 00 2b 13 04 11 04 } //5
		$a_01_1 = {37 00 43 00 35 00 38 00 34 00 47 00 38 00 47 00 46 00 38 00 46 00 49 00 47 00 48 00 48 00 34 00 37 00 53 00 37 00 5a 00 35 00 34 00 } //1 7C584G8GF8FIGHH47S7Z54
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}