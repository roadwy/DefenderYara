
rule Trojan_BAT_Fsysna_IOAA_MTB{
	meta:
		description = "Trojan:BAT/Fsysna.IOAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 25 17 6f ?? 00 00 0a 25 18 6f ?? 00 00 0a 25 11 0a 6f ?? 00 00 0a 25 11 09 6f ?? 00 00 0a 6f ?? 00 00 0a 11 08 16 11 08 8e 69 6f ?? 00 00 0a 13 08 } //5
		$a_01_1 = {50 00 61 00 79 00 61 00 72 00 65 00 74 00 } //1 Payaret
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}