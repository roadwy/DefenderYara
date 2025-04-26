
rule Trojan_BAT_Seraph_AMBA_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AMBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 0a 11 07 11 05 11 07 28 ?? 00 00 06 20 ?? ?? 00 00 61 d1 9d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Seraph_AMBA_MTB_2{
	meta:
		description = "Trojan:BAT/Seraph.AMBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 06 11 03 11 01 11 03 91 11 00 59 d2 9c 20 ?? 00 00 00 38 ?? ff ff ff 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_BAT_Seraph_AMBA_MTB_3{
	meta:
		description = "Trojan:BAT/Seraph.AMBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 16 d2 13 2b 11 16 1e 63 d1 13 16 11 1e 11 09 91 13 23 11 1e 11 09 11 25 11 23 61 19 11 1d 58 61 11 2b 61 d2 9c 11 09 17 58 13 09 11 23 13 1d 11 09 11 27 32 a4 } //1
		$a_01_1 = {11 33 11 13 11 0f 11 13 91 9d 17 11 13 58 13 13 11 13 11 1f 32 ea } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}