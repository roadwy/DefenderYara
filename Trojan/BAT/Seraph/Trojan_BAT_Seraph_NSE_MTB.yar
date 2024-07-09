
rule Trojan_BAT_Seraph_NSE_MTB{
	meta:
		description = "Trojan:BAT/Seraph.NSE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {8f 10 00 00 01 25 47 07 08 07 8e 69 5d 91 61 d2 52 08 17 58 0c 08 06 8e 69 } //5
		$a_01_1 = {45 76 61 64 69 6e 67 53 70 6f 6f 66 65 72 } //1 EvadingSpoofer
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_Seraph_NSE_MTB_2{
	meta:
		description = "Trojan:BAT/Seraph.NSE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 01 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 06 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 73 ?? 00 00 0a 0c 28 ?? 00 00 06 75 ?? 00 00 1b 73 ?? 00 00 0a 0d 09 07 16 73 18 00 00 0a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}