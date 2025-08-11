
rule Trojan_BAT_Rhadamanthys_RK_MTB{
	meta:
		description = "Trojan:BAT/Rhadamanthys.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 1f 10 8d 1d 00 00 01 25 d0 55 02 00 04 28 6f 00 00 0a 6f d6 00 00 0a 06 07 6f d7 00 00 0a 17 73 3b 00 00 0a 25 02 16 02 8e 69 6f d8 00 00 0a 6f d9 00 00 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}