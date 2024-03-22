
rule Trojan_Win32_StealC_YX_MTB{
	meta:
		description = "Trojan:Win32/StealC.YX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {01 45 ec 8b 45 ec 31 45 f0 8b 45 f8 33 45 f0 2b f0 89 45 f8 8b c6 c1 e0 04 89 45 fc 8b 45 d8 } //00 00 
	condition:
		any of ($a_*)
 
}