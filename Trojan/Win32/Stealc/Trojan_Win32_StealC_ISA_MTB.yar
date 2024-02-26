
rule Trojan_Win32_StealC_ISA_MTB{
	meta:
		description = "Trojan:Win32/StealC.ISA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 8d f8 fb ff ff 30 04 39 83 fb 0f 75 1f } //01 00 
		$a_03_1 = {a1 8c ef 42 00 89 85 6c f3 ff ff b8 31 a2 00 00 01 85 6c f3 ff ff a1 90 01 04 03 85 70 f3 ff ff 8b 8d 6c f3 ff ff 03 8d 70 f3 ff ff 8a 09 88 08 81 3d 90 01 04 ab 05 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}