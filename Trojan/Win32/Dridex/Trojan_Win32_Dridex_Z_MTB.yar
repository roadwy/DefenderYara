
rule Trojan_Win32_Dridex_Z_MTB{
	meta:
		description = "Trojan:Win32/Dridex.Z!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b cb 33 d6 4a 02 c4 2b da 8b d9 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}