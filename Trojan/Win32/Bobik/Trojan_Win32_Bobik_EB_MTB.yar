
rule Trojan_Win32_Bobik_EB_MTB{
	meta:
		description = "Trojan:Win32/Bobik.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 0f b6 44 10 10 33 c8 66 3b ed 74 09 } //02 00 
		$a_01_1 = {8b 45 ec 03 45 f0 88 08 e9 49 01 } //02 00 
		$a_01_2 = {8b 45 ec 03 45 f0 0f b6 08 3a ed 74 86 } //00 00 
	condition:
		any of ($a_*)
 
}