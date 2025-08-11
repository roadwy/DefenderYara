
rule Trojan_Win64_Stealc_GB_MTB{
	meta:
		description = "Trojan:Win64/Stealc.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c1 42 8a 0c 08 32 0c 32 48 8d 55 ?? 88 4d ?? 49 8b ce e8 ?? ?? ?? ?? 48 ff c6 49 3b 75 ?? 72 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}