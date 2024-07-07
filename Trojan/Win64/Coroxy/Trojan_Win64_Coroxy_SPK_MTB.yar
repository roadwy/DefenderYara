
rule Trojan_Win64_Coroxy_SPK_MTB{
	meta:
		description = "Trojan:Win64/Coroxy.SPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8d 0d 76 0f 00 00 0f be 04 01 8b 4c 24 28 33 c8 8b c1 48 63 4c 24 20 48 8b 54 24 30 88 04 0a eb a6 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}