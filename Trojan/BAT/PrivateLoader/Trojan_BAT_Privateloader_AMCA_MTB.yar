
rule Trojan_BAT_Privateloader_AMCA_MTB{
	meta:
		description = "Trojan:BAT/Privateloader.AMCA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 16 1f 10 28 ?? 00 00 0a 00 73 ?? 00 00 0a 08 09 6f ?? 00 00 0a 13 04 04 73 ?? 00 00 0a 13 05 73 ?? 00 00 0a 13 06 00 11 05 11 04 16 73 ?? 00 00 0a 13 07 00 11 07 11 06 6f ?? 00 00 0a 00 00 de } //2
		$a_80_1 = {37 51 51 72 65 74 72 65 74 72 65 74 72 65 74 72 65 74 72 65 4b 59 } //7QQretretretretretreKY  2
	condition:
		((#a_03_0  & 1)*2+(#a_80_1  & 1)*2) >=4
 
}