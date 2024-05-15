
rule Trojan_Win32_IcedID_KQ_MTB{
	meta:
		description = "Trojan:Win32/IcedID.KQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 db 8a 4c 1c 90 01 01 0f b6 d1 02 c2 0f b6 c0 89 44 24 90 01 01 8a 44 04 90 01 01 88 44 1c 90 01 01 8b 44 24 90 01 01 88 4c 04 90 01 01 8a 44 1c 90 01 01 02 c2 0f b6 c0 8a 44 04 90 01 01 32 04 3e 88 07 47 8b 44 24 90 01 01 83 ed 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}