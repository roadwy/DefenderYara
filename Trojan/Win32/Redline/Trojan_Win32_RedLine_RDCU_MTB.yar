
rule Trojan_Win32_RedLine_RDCU_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RDCU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {03 cf 33 c2 33 c1 2b f0 8b d6 c1 e2 04 } //00 00 
	condition:
		any of ($a_*)
 
}