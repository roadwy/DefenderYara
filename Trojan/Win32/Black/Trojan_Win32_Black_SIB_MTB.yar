
rule Trojan_Win32_Black_SIB_MTB{
	meta:
		description = "Trojan:Win32/Black.SIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {57 0f b7 f7 59 90 18 5f 90 18 81 c7 90 01 04 90 02 10 33 db 90 02 10 ff 34 3b 90 02 10 58 81 c0 90 01 04 90 02 10 81 f0 90 01 04 90 02 10 81 f0 90 01 04 50 90 02 10 8f 04 1f 90 02 10 83 eb 90 01 01 90 02 10 81 fb 90 01 04 90 18 90 02 10 90 18 ff 34 3b 90 02 10 58 81 c0 90 1b 06 90 02 10 81 f0 90 1b 08 90 02 10 81 f0 90 01 04 50 90 02 10 8f 04 1f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}