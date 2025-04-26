
rule Trojan_BAT_Rubeus_NR_MTB{
	meta:
		description = "Trojan:BAT/Rubeus.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {08 6f df 06 00 06 16 9a 6f 04 07 00 06 28 f0 06 00 06 6f df 06 00 06 16 9a 14 73 1a 01 00 06 } //2
		$a_01_1 = {6f df 06 00 06 17 9a 6f df 06 00 06 16 9a 6f 04 07 00 06 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}