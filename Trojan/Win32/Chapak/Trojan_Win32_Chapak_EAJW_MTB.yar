
rule Trojan_Win32_Chapak_EAJW_MTB{
	meta:
		description = "Trojan:Win32/Chapak.EAJW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 00 33 85 68 ff ff ff 8b 8d 54 ff ff ff 89 01 81 7d f8 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}