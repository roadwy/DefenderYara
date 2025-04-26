
rule Trojan_Win32_Razy_CCGM_MTB{
	meta:
		description = "Trojan:Win32/Razy.CCGM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 47 28 31 06 83 c6 04 3b 37 0f 82 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}