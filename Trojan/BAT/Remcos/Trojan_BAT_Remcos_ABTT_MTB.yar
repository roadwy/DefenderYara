
rule Trojan_BAT_Remcos_ABTT_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ABTT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {4c 00 6f 00 6f 00 6d 00 69 00 73 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 } //2
		$a_01_1 = {31 34 66 37 35 39 62 65 2d 62 36 65 65 2d 34 39 65 63 2d 38 37 62 62 2d 39 38 33 61 39 63 63 64 66 30 35 31 } //1 14f759be-b6ee-49ec-87bb-983a9ccdf051
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}