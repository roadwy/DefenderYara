
rule Trojan_Win32_Injuke_RJ_MTB{
	meta:
		description = "Trojan:Win32/Injuke.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {c1 ea 05 c7 05 90 01 04 84 10 d6 cb c7 05 90 01 04 ff ff ff ff 89 54 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 8b 44 24 90 01 01 03 f0 03 eb 33 f5 33 74 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}