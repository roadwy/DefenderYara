
rule Trojan_Win64_XWorm_SDEL_MTB{
	meta:
		description = "Trojan:Win64/XWorm.SDEL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 c9 31 d2 45 31 c9 ff 15 fb 55 ff ff 48 8b 0d fc b0 ff ff 4c 63 59 04 8b 0d ce a3 ff ff 8b 15 cc a3 ff ff 8d 69 ff 0f af e9 89 e9 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}