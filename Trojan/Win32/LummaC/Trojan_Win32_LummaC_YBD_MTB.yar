
rule Trojan_Win32_LummaC_YBD_MTB{
	meta:
		description = "Trojan:Win32/LummaC.YBD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 0f 10 45 e0 0f 57 05 ?? ?? ?? ?? 0f 11 45 e0 0f 10 45 f0 0f 57 05 ?? ?? ?? ?? 0f 11 45 f0 f2 0f 10 45 e0 f2 0f 10 4d e8 f2 0f 10 5d f0 f2 0f 10 55 } //11
	condition:
		((#a_03_0  & 1)*11) >=11
 
}