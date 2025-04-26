
rule Trojan_Win64_Cryptinject_YBC_MTB{
	meta:
		description = "Trojan:Win64/Cryptinject.YBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 2b c8 49 0f af cf 0f b6 44 0d 8f 43 32 44 18 fc 41 88 40 fc 41 8d 42 ff 48 63 c8 48 8b c3 48 f7 e1 } //11
	condition:
		((#a_01_0  & 1)*11) >=11
 
}