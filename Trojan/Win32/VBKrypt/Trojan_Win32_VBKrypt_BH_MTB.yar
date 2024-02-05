
rule Trojan_Win32_VBKrypt_BH_MTB{
	meta:
		description = "Trojan:Win32/VBKrypt.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {c1 e1 00 8b 99 90 02 1f 53 90 02 1f 81 34 24 90 02 1f 8f 04 08 90 02 1f 41 90 02 2f 83 c1 f8 7d 90 02 1f ff e0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}