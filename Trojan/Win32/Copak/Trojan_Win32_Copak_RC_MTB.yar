
rule Trojan_Win32_Copak_RC_MTB{
	meta:
		description = "Trojan:Win32/Copak.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 04 03 01 f7 8b 00 89 f7 81 e0 ff 00 00 00 09 f7 43 81 c6 ba 60 9e d3 89 f7 81 fb f4 01 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}