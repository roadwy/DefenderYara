
rule Trojan_Win32_Neoreblamy_NLQ_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NLQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 d8 40 89 45 d8 83 7d d8 02 7d 10 8b 45 d8 } //2
		$a_01_1 = {eb 07 8b 45 e4 48 89 45 e4 83 7d e4 10 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}