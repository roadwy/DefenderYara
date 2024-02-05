
rule Trojan_Win32_Bunitu_BA_MTB{
	meta:
		description = "Trojan:Win32/Bunitu.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {81 ea 2d ad 00 00 89 15 90 01 04 a1 90 01 04 03 85 90 01 04 03 05 90 01 04 a3 90 01 04 8b 0d 90 01 04 2b 0d 90 01 04 89 0d 90 00 } //01 00 
		$a_02_1 = {03 f8 68 6f d0 06 00 ff 15 90 01 04 03 45 90 01 01 8b 55 90 01 01 8a 0c 32 88 0c 38 8b 55 90 01 01 83 c2 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}