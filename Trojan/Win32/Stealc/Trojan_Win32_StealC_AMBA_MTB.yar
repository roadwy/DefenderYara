
rule Trojan_Win32_StealC_AMBA_MTB{
	meta:
		description = "Trojan:Win32/StealC.AMBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c2 d3 e8 8b 4d 90 01 01 03 c3 33 45 90 01 01 33 c8 8d 45 90 01 01 89 4d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_StealC_AMBA_MTB_2{
	meta:
		description = "Trojan:Win32/StealC.AMBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 ec 08 04 00 00 a1 90 01 04 33 c5 89 85 90 00 } //01 00 
		$a_01_1 = {8b 8d f8 fb ff ff 30 04 31 83 fb 0f 75 } //00 00 
	condition:
		any of ($a_*)
 
}