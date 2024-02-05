
rule Trojan_Win32_Gozi_ME_MTB{
	meta:
		description = "Trojan:Win32/Gozi.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {0f b7 d1 53 8b 1d 90 01 04 56 8b c8 81 f1 ff 5a 17 43 8b 0c 19 03 cb 57 0f b7 79 06 47 8b f0 81 f6 eb 5a 17 43 0f af fe 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}