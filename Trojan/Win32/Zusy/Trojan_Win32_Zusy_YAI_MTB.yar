
rule Trojan_Win32_Zusy_YAI_MTB{
	meta:
		description = "Trojan:Win32/Zusy.YAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 01 00 00 "
		
	strings :
		$a_03_0 = {ac 02 c3 32 c3 02 c3 90 13 32 c3 2a c3 32 c3 2a c3 90 13 c0 c8 2d aa 83 } //11
	condition:
		((#a_03_0  & 1)*11) >=11
 
}