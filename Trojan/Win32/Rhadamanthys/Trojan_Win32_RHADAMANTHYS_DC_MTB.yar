
rule Trojan_Win32_RHADAMANTHYS_DC_MTB{
	meta:
		description = "Trojan:Win32/RHADAMANTHYS.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b c1 33 d0 0f af 95 24 fd ff ff 89 95 50 e0 ff ff 8b 95 50 e0 ff ff 89 95 4c e0 ff ff 8b 85 4c e0 ff ff 83 e8 01 89 85 48 e0 ff ff c7 85 4c ef ff ff 01 00 00 00 51 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}