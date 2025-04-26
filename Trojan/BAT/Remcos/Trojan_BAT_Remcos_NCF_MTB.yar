
rule Trojan_BAT_Remcos_NCF_MTB{
	meta:
		description = "Trojan:BAT/Remcos.NCF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 19 8d 3b 00 00 01 25 16 06 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 06 1e 63 20 ff 00 00 00 5f d2 9c 25 18 06 20 ff 00 00 00 5f d2 9c 6f 48 00 00 0a 00 2a } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}