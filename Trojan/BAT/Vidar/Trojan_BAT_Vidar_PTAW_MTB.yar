
rule Trojan_BAT_Vidar_PTAW_MTB{
	meta:
		description = "Trojan:BAT/Vidar.PTAW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {6f 31 00 00 0a 72 06 03 00 70 6f 4a 00 00 0a 73 47 00 00 0a 25 6f 41 00 00 0a 16 6a 6f 42 00 00 0a 25 25 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}