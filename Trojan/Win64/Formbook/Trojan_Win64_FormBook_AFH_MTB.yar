
rule Trojan_Win64_FormBook_AFH_MTB{
	meta:
		description = "Trojan:Win64/FormBook.AFH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 45 da 0f b6 45 e7 34 28 88 45 db 0f b6 45 e7 34 3f 88 45 dc 0f b6 45 e7 34 3b 88 45 dd 0f b6 45 e7 34 3e 88 45 de 0f b6 45 e7 34 5a 88 45 df } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}