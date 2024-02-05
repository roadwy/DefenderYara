
rule Trojan_Win32_VBkrypt_GD_MTB{
	meta:
		description = "Trojan:Win32/VBkrypt.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {83 f9 00 7d 90 02 19 ff d0 90 0a 64 00 8b 14 0f 90 02 28 31 f2 90 02 0a 09 14 08 90 02 19 83 e9 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}