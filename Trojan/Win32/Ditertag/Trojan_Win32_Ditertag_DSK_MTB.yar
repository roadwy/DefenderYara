
rule Trojan_Win32_Ditertag_DSK_MTB{
	meta:
		description = "Trojan:Win32/Ditertag.DSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_00_0 = {8b 4d d0 89 c2 83 ca 01 d3 ff 0f af d1 03 7d 08 29 d0 03 45 08 8a 17 ff 4d ec 88 55 cf 8a 10 88 17 8a 55 cf 88 10 75 } //02 00 
		$a_02_1 = {8b 55 e0 89 54 24 04 e8 90 01 04 89 f1 d3 ff 09 f0 03 45 08 03 7d 08 ff 4d e8 8a 08 8a 17 88 0f 88 10 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}