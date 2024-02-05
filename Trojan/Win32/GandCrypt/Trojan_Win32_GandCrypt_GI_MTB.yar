
rule Trojan_Win32_GandCrypt_GI_MTB{
	meta:
		description = "Trojan:Win32/GandCrypt.GI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 d8 c7 05 90 01 04 2e ce 50 91 a1 90 01 04 81 fa a9 0f 00 00 89 5c 24 18 bb 40 2e eb ed 0f 44 c3 8b df c1 eb 05 03 d9 a3 90 01 04 8d 04 3e 81 fa 76 09 00 00 75 90 01 01 33 c9 8d 84 24 90 01 04 51 51 50 51 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}