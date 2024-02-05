
rule Trojan_Win32_DelpInj_MTB{
	meta:
		description = "Trojan:Win32/DelpInj!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 45 fc 0f b6 44 38 ff 33 45 f8 89 45 f4 8d 45 f0 8a 55 f4 e8 90 01 04 8b 55 f0 8b c6 e8 90 01 04 47 4b 75 d9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}