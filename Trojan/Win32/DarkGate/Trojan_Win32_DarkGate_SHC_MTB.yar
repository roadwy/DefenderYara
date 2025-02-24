
rule Trojan_Win32_DarkGate_SHC_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.SHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {64 a1 30 00 00 00 60 89 f9 0f 95 c0 89 f9 85 ff 0f 44 c1 81 e7 ff ff fd ff bb 01 00 00 00 83 e1 08 09 c8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}