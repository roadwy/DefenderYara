
rule Trojan_Win32_Darkgate_YAD_MTB{
	meta:
		description = "Trojan:Win32/Darkgate.YAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 01 00 00 "
		
	strings :
		$a_01_0 = {61 30 04 0f 66 0f 57 c9 41 f2 0f 5f c8 89 c8 66 0f 55 c1 } //11
	condition:
		((#a_01_0  & 1)*11) >=11
 
}