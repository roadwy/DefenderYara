
rule Trojan_BAT_Redline_PSSW_MTB{
	meta:
		description = "Trojan:BAT/Redline.PSSW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 9b 00 00 0a 0a dd 20 00 00 00 26 72 03 00 00 70 72 a2 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 74 7e 00 00 01 0a dd 00 00 00 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}