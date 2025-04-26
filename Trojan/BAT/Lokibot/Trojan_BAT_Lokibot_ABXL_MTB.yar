
rule Trojan_BAT_Lokibot_ABXL_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.ABXL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 00 61 00 74 00 61 00 42 00 61 00 73 00 65 00 50 00 72 00 61 00 63 00 74 00 69 00 63 00 61 00 6c 00 4a 00 6f 00 62 00 } //2 DataBasePracticalJob
		$a_01_1 = {52 00 61 00 74 00 69 00 6f 00 4d 00 61 00 73 00 74 00 65 00 72 00 5f 00 73 00 6f 00 75 00 72 00 63 00 65 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}