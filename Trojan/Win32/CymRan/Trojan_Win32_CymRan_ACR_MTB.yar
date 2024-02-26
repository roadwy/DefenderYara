
rule Trojan_Win32_CymRan_ACR_MTB{
	meta:
		description = "Trojan:Win32/CymRan.ACR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {2b 55 fc 52 8b 45 10 03 45 fc 50 8b 4d 0c 03 4d fc 51 8b 55 08 52 ff 15 f4 90 43 00 85 c0 } //00 00 
	condition:
		any of ($a_*)
 
}