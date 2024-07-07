
rule Trojan_BAT_Xmrig_CBC_MTB{
	meta:
		description = "Trojan:BAT/Xmrig.CBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {28 03 00 00 06 28 02 00 00 06 28 90 01 01 00 00 0a 72 90 01 03 70 28 03 00 00 06 6f 90 01 01 00 00 0a 02 1f 18 6f 90 01 01 00 00 0a 14 03 6f 90 01 01 00 00 0a a5 3a 00 00 01 0a de 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}