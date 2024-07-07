
rule Trojan_BAT_Injuke_SRQP_MTB{
	meta:
		description = "Trojan:BAT/Injuke.SRQP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {9a 2b 4b 06 09 6f 90 01 03 0a 6f 90 01 03 0a 08 17 58 16 2d fb 16 2d f8 0c 08 07 8e 69 32 dd 06 2a 73 1f 00 00 0a 38 a3 ff ff ff 28 90 01 03 06 38 a2 ff ff ff 6f 90 01 03 0a 38 9d ff ff ff 0a 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}