
rule Trojan_Win32_Zusy_AMBE_MTB{
	meta:
		description = "Trojan:Win32/Zusy.AMBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {c0 c8 03 32 83 90 01 04 6a 0d 88 81 90 01 04 8d 43 01 99 5b f7 fb 41 8b da 3b ce 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}