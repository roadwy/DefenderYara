
rule Trojan_Win32_Zusy_RPR_MTB{
	meta:
		description = "Trojan:Win32/Zusy.RPR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 34 81 e9 90 09 01 00 ?? ?? ?? ?? 90 13 40 90 13 3b c2 90 13 0f 82 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}