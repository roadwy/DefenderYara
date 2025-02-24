
rule Trojan_BAT_Remcos_AOHA_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AOHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {01 25 16 11 08 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 11 08 1e 63 20 ff 00 00 00 5f d2 9c 25 18 11 08 20 ff 00 00 00 5f d2 9c } //4
		$a_03_1 = {01 25 16 12 05 28 ?? 00 00 0a 9c 25 17 12 05 28 ?? 00 00 0a 9c 25 18 12 05 28 ?? 00 00 0a 9c } //2
	condition:
		((#a_01_0  & 1)*4+(#a_03_1  & 1)*2) >=6
 
}