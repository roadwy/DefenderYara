
rule Trojan_BAT_Remcos_AMAI_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AMAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 17 58 20 ff 00 00 00 5f 0d [0-0a] 09 95 58 20 ff 00 00 00 } //1
		$a_03_1 = {95 16 61 d2 13 [0-0f] 61 16 60 d2 13 [0-14] 20 ff 00 00 00 5f d2 9c } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}