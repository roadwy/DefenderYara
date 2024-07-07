
rule Trojan_Win32_SDBot_PABL_MTB{
	meta:
		description = "Trojan:Win32/SDBot.PABL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 ad ec ff ff ff 2e ff a4 91 8b 3b 81 85 d8 ff ff ff 8e 6b bb ba 33 fe 81 85 d8 ff ff ff e8 e0 20 49 89 3a 81 c2 83 fa d8 b6 81 ea 7f fa d8 b6 81 c3 ad 98 ab 0d 81 eb a9 98 ab 0d e2 c2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}