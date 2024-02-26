
rule Trojan_Win32_Injuke_ASB_MTB{
	meta:
		description = "Trojan:Win32/Injuke.ASB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {2a 01 00 00 00 99 ca 84 00 36 29 81 00 00 da 0a 00 73 5b 0d ca f9 eb 80 00 00 d4 00 00 69 a6 15 46 00 00 01 } //00 00 
	condition:
		any of ($a_*)
 
}