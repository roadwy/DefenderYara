
rule Trojan_BAT_Mardom_SFA_MTB{
	meta:
		description = "Trojan:BAT/Mardom.SFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {28 0a 00 00 0a 0d 07 28 0b 00 00 0a 2d 2b 28 0c 00 00 0a 28 0d 00 00 0a 28 0e 00 00 0a 72 ?? ?? ?? 70 28 0f 00 00 0a 13 04 11 04 09 28 10 00 00 0a 11 04 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}