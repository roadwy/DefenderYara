
rule Trojan_Win32_Emotet_VAD_MTB{
	meta:
		description = "Trojan:Win32/Emotet.VAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {30 df 8b 54 24 54 8b 44 24 50 89 c6 0f af f2 89 44 24 04 8b 54 24 04 f7 e2 01 f2 01 f2 89 44 24 ?? 89 54 24 ?? 8a 5c 24 33 80 f3 3b 88 5c 24 4f 8b 44 24 48 35 18 d6 70 66 8b 54 24 2c 88 3c 0a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}