
rule Trojan_BAT_Vidar_PTBO_MTB{
	meta:
		description = "Trojan:BAT/Vidar.PTBO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 17 0a 72 01 00 00 70 0b 73 14 00 00 0a 07 28 ?? 00 00 0a 0c 08 8e } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}