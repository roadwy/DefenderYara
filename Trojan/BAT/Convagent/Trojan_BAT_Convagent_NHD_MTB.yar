
rule Trojan_BAT_Convagent_NHD_MTB{
	meta:
		description = "Trojan:BAT/Convagent.NHD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {02 14 7d 01 00 00 04 02 28 ?? 00 00 0a 00 00 02 28 ?? 00 00 06 00 72 ?? 00 00 70 0a 06 73 ?? 00 00 0a 0b 07 6f ?? 00 00 0a 00 72 ?? 00 00 70 0c 08 07 73 ?? 00 00 0a 0d 09 6f ?? 00 00 0a 6f ?? 00 00 0a 13 04 02 7b ?? 00 00 04 11 04 6f ?? 00 00 0a 00 07 6f ?? 00 00 0a } //5
		$a_01_1 = {50 72 6f 67 72 61 6d 6d 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 Programm.Properties.Resources
		$a_01_2 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 6e 00 61 00 6d 00 65 00 20 00 46 00 52 00 4f 00 4d 00 20 00 74 00 65 00 73 00 74 00 31 00 } //1 SELECT name FROM test1
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}