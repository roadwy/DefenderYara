
rule Trojan_Win32_CryptBot_CX_MTB{
	meta:
		description = "Trojan:Win32/CryptBot.CX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {33 c8 40 3d 90 01 04 7c 90 01 01 8b 45 08 32 ca 80 f1 90 01 01 88 0c 06 b9 90 01 04 46 3b f7 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}