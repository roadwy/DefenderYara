
rule Trojan_BAT_Vidar_CQ_MTB{
	meta:
		description = "Trojan:BAT/Vidar.CQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {28 a4 00 00 06 28 89 ?? ?? ?? 72 3d 05 00 70 72 41 05 00 70 28 a5 00 00 06 72 49 05 00 70 72 4d 05 00 70 28 a5 00 00 06 72 51 05 00 70 72 01 05 00 70 6f 8a 00 00 0a 13 01 20 ?? ?? ?? ?? 28 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}