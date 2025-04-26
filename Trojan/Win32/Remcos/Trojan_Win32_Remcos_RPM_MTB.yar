
rule Trojan_Win32_Remcos_RPM_MTB{
	meta:
		description = "Trojan:Win32/Remcos.RPM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 65 e8 8b 4d c8 88 4d e1 c7 45 fc fe ff ff ff 8b 5d a8 8b 75 bc 8a 45 e0 8b 7d d8 83 bd 14 01 00 00 00 75 03 8a 45 e1 88 04 39 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}