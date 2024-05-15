
rule Trojan_Win32_Zenpak_ASAG_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.ASAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {0f b6 c8 8b 55 f8 31 ca 88 d4 } //02 00 
		$a_01_1 = {55 89 e5 83 ec 0c 8a 45 0c 8a 4d 08 88 45 ff 88 4d fe } //00 00 
	condition:
		any of ($a_*)
 
}