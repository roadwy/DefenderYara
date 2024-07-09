
rule Trojan_Win32_Zusy_CREL_MTB{
	meta:
		description = "Trojan:Win32/Zusy.CREL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 04 13 30 c8 88 44 24 24 89 cf d1 ?? 81 e7 ?? ?? ?? ?? 89 fb 81 f3 ?? ?? ?? ?? f6 c1 ?? 0f 44 df 8b 44 24 28 8a 4c 24 24 88 0c 10 8b 44 24 28 42 89 d9 8b 5c 24 34 39 d6 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}