
rule Trojan_Win32_Upatre_DSK_MTB{
	meta:
		description = "Trojan:Win32/Upatre.DSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_02_0 = {89 d0 0f b6 80 90 01 04 0f b6 55 90 01 01 31 c2 8b 45 90 01 01 05 90 01 04 88 10 83 45 90 01 01 01 a1 90 01 04 39 45 90 01 01 7c 90 00 } //02 00 
		$a_02_1 = {89 d0 0f b6 80 90 01 04 89 c1 8b 55 f4 8b 45 08 01 d0 0f b6 55 e7 31 ca 88 10 83 45 f4 01 8b 45 f4 3b 45 0c 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}