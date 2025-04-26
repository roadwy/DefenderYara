
rule Trojan_Win32_Remcos_CCHT_MTB{
	meta:
		description = "Trojan:Win32/Remcos.CCHT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 ca 8a 8c 0d ?? ?? ff ff 30 0e e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}