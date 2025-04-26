
rule Trojan_BAT_MeduzaStealer_AME_MTB{
	meta:
		description = "Trojan:BAT/MeduzaStealer.AME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 0a 06 28 39 00 00 0a 7d 1c 00 00 04 06 02 7d 1e 00 00 04 06 03 7d 1d 00 00 04 06 15 7d 1b 00 00 04 06 7c 1c 00 00 04 12 00 28 01 00 00 2b 06 7c 1c 00 00 04 28 } //2
		$a_03_1 = {0a 00 06 02 7b 07 00 00 04 6f ?? 00 00 0a 00 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 73 42 00 00 0a 0c 08 07 17 73 43 00 00 0a 0d 09 73 44 00 00 0a 13 04 00 11 04 03 6f } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}