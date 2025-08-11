
rule Trojan_Win32_Zusy_CCJX_MTB{
	meta:
		description = "Trojan:Win32/Zusy.CCJX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 8a 0c 01 30 0c 17 47 3b 7d ?? 0f 82 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}