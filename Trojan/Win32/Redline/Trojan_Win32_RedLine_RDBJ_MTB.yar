
rule Trojan_Win32_RedLine_RDBJ_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RDBJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {f7 75 14 8b 4d 10 0f b6 14 11 8b 45 08 03 45 cc 0f b6 08 2b ca 8b 55 08 03 55 cc 88 0a } //00 00 
	condition:
		any of ($a_*)
 
}