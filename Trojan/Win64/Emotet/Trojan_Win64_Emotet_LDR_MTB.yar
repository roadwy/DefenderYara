
rule Trojan_Win64_Emotet_LDR_MTB{
	meta:
		description = "Trojan:Win64/Emotet.LDR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 f7 75 10 49 8b 45 08 45 03 ca 8a 0c 02 42 32 0c 03 41 88 08 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}