
rule Trojan_Win32_Neoreblamy_RR_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6a 16 59 33 d2 8b c6 f7 f1 8b 45 08 8b 0c b3 8b 14 90 e8 cc ff ff ff 89 04 b3 46 3b f7 72 e1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}