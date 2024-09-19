
rule Trojan_Win64_Redline_MAA_MTB{
	meta:
		description = "Trojan:Win64/Redline.MAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 98 0f b6 44 05 ?? 48 63 8d ?? ?? ?? ?? 48 8b 95 ?? ?? ?? ?? 0f b6 0c 0a 33 c8 8b c1 48 63 8d ?? ?? ?? ?? 48 8b 95 ?? ?? ?? ?? 88 04 0a e9 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}