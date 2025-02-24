
rule Trojan_Win32_Neoreblamy_NQ_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {6a 04 58 6b c0 00 8b 84 05 ?? ff ff ff 89 45 cc 8b 45 cc } //1
		$a_01_1 = {6a 04 58 c1 e0 00 8b 84 05 cc fd ff ff 48 6a 04 59 c1 e1 00 89 84 0d cc fd ff ff 6a 04 58 c1 e0 00 } //2
		$a_01_2 = {eb 1b 6a 04 58 6b c0 00 8b 84 05 0c ff ff ff 48 6a 04 59 6b c9 00 89 84 0d 0c ff ff ff 6a 04 58 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=4
 
}