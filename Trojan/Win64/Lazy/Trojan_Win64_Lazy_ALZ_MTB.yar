
rule Trojan_Win64_Lazy_ALZ_MTB{
	meta:
		description = "Trojan:Win64/Lazy.ALZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 83 ec 28 48 8d 0d f5 e2 00 00 31 d2 ff 15 } //1
		$a_01_1 = {48 8d 0d c6 e2 00 00 31 d2 ff 15 be df 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}