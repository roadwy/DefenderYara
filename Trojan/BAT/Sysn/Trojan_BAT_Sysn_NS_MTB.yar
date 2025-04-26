
rule Trojan_BAT_Sysn_NS_MTB{
	meta:
		description = "Trojan:BAT/Sysn.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {8e 69 17 63 8f ?? 00 00 01 25 47 06 1a 58 4a d2 61 d2 52 28 ?? 00 00 0a 07 6f ?? 00 00 0a 28 ?? 00 00 0a 2a } //5
		$a_01_1 = {41 75 74 68 65 6e 6e 74 69 63 61 74 65 20 40 32 30 32 33 } //1 Authennticate @2023
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}