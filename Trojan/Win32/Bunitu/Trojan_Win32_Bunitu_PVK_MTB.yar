
rule Trojan_Win32_Bunitu_PVK_MTB{
	meta:
		description = "Trojan:Win32/Bunitu.PVK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 02 00 "
		
	strings :
		$a_02_0 = {0f b6 44 24 07 88 99 90 01 04 0f b6 9a 90 01 04 03 d8 81 f9 59 22 00 00 73 90 00 } //02 00 
		$a_02_1 = {8b ff 33 3d 90 01 04 8b cf b8 04 00 00 00 03 c1 83 e8 04 a3 90 01 04 a1 90 01 04 8b 0d 90 01 04 89 08 90 00 } //02 00 
		$a_02_2 = {b4 ca 48 21 5e da 08 ba 90 01 04 80 f3 09 eb 90 00 } //02 00 
		$a_02_3 = {f6 d2 0a ca 22 cb 88 08 83 c0 01 83 6c 24 90 01 01 01 89 44 24 90 01 01 0f 85 90 09 04 00 8b 44 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}