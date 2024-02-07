
rule Trojan_Win32_GuLoader_AM_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {39 cb d9 d0 90 02 08 75 90 0a 50 00 4a 90 02 15 29 db 90 02 15 0b 1a 90 02 20 39 cb d9 d0 90 02 08 75 90 00 } //01 00 
		$a_03_1 = {46 85 ff 8b 0f 90 02 08 0f 6e c6 90 02 08 0f 6e c9 90 02 08 0f ef c8 90 02 08 0f 7e c9 90 02 08 39 c1 90 02 08 75 90 00 } //00 00 
		$a_00_2 = {7e } //15 00  ~
	condition:
		any of ($a_*)
 
}