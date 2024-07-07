
rule Trojan_BAT_DarkTortilla_AAXQ_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.AAXQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 08 1f 20 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 00 09 08 1f 10 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 00 09 09 6f 90 01 01 00 00 0a 09 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 13 04 00 73 90 01 01 00 00 0a 13 05 00 11 05 11 04 17 73 90 01 01 00 00 0a 13 07 11 07 02 16 02 8e 69 6f 90 01 01 00 00 0a 00 11 07 6f 90 01 01 00 00 0a 00 de 0e 90 00 } //4
		$a_01_1 = {4c 00 2e 00 6f 00 2e 00 61 00 2e 00 64 00 2e 00 } //1 L.o.a.d.
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}