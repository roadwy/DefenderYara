
rule Trojan_BAT_Taskun_ETL_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ETL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 76 00 00 06 0a 06 03 7d 4f 00 00 04 06 fe 06 77 00 00 06 73 d4 00 00 0a 0c 02 08 6f d5 00 00 0a 17 73 d6 00 00 0a 0b } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}