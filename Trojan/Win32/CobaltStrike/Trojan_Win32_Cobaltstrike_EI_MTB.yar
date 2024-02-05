
rule Trojan_Win32_Cobaltstrike_EI_MTB{
	meta:
		description = "Trojan:Win32/Cobaltstrike.EI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {03 d8 8b 45 ec 89 18 8b 45 d8 03 45 b0 03 45 e8 89 45 b4 8b 45 b4 8b 55 ec 31 02 83 45 e8 04 83 45 ec 04 8b 45 e8 3b 45 e4 72 } //00 00 
	condition:
		any of ($a_*)
 
}