
rule Trojan_BAT_Strictor_PAQ_MTB{
	meta:
		description = "Trojan:BAT/Strictor.PAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 65 62 3d bf 65 20 01 a9 71 13 61 7e 9f 00 00 04 7b 72 00 00 04 61 28 ?? ?? ?? 06 11 03 73 25 00 00 0a 13 02 20 00 00 00 00 7e 9f 00 00 04 7b 8a 00 00 04 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}