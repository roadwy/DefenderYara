
rule Trojan_BAT_Fsysna_SID_MTB{
	meta:
		description = "Trojan:BAT/Fsysna.SID!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 7b 99 00 00 04 02 7b 9b 00 00 04 02 7b ac 00 00 04 6f 57 00 00 06 28 cc 00 00 0a 06 17 28 cd 00 00 0a 72 82 39 00 70 28 20 00 00 06 72 ab 38 00 70 28 20 00 00 06 28 ce 00 00 0a 72 82 39 00 70 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}