
rule Trojan_BAT_SelfDel_GTN_MTB{
	meta:
		description = "Trojan:BAT/SelfDel.GTN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 09 91 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 5d 13 04 06 09 72 ?? ?? ?? 70 11 04 28 ?? ?? ?? 0a 9d 09 17 58 0d 09 02 32 d9 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}