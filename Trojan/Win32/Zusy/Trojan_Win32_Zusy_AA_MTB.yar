
rule Trojan_Win32_Zusy_AA_MTB{
	meta:
		description = "Trojan:Win32/Zusy.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {53 8b da c1 eb ?? 8b 07 69 f6 ?? ?? ?? ?? 69 c0 ?? ?? ?? ?? 8b c8 c1 e9 ?? 33 c8 69 c9 95 e9 d1 5b 33 f1 83 ea ?? 83 c7 ?? 4b 75 da } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}