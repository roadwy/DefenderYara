
rule Trojan_Win64_Mikey_GMN_MTB{
	meta:
		description = "Trojan:Win64/Mikey.GMN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {0a 59 b8 a4 42 30 f3 8a cb 5e 85 0a 24 a2 1a ef b7 20 } //5
		$a_01_1 = {f6 03 1d 8f 41 5b 5a 91 33 50 10 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}