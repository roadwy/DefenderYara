
rule Trojan_Win32_Zenpak_ASAF_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.ASAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_01_0 = {0f b6 55 fb 0f b6 75 fa 31 f2 88 d0 0f b6 c0 83 c4 04 5e 5d c3 } //01 00 
		$a_01_1 = {55 89 e5 56 50 8a 45 0c 8a 4d 08 88 45 fa 88 4d fb } //00 00 
	condition:
		any of ($a_*)
 
}