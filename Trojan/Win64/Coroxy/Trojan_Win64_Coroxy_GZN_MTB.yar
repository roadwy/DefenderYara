
rule Trojan_Win64_Coroxy_GZN_MTB{
	meta:
		description = "Trojan:Win64/Coroxy.GZN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 2b c8 49 0f af ?? 0f b6 44 0c ?? 49 63 cf 43 32 44 0b ?? 41 88 41 ?? 49 8b c5 48 f7 e1 48 8b c1 48 2b c2 48 d1 e8 48 03 c2 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}