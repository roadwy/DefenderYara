
rule Trojan_Win32_Phorpiex_NP_MTB{
	meta:
		description = "Trojan:Win32/Phorpiex.NP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {d1 e8 89 45 f0 0f b6 4d 90 01 01 85 c9 74 0c 8b 55 f0 81 f2 90 01 04 89 55 f0 eb c4 8b 45 90 01 01 33 45 f0 89 45 90 01 01 eb 84 90 00 } //01 00 
		$a_01_1 = {3a 00 2f 00 2f 00 31 00 38 00 35 00 2e 00 32 00 31 00 35 00 2e 00 31 00 31 00 33 00 2e 00 39 00 33 00 2f 00 70 00 69 00 2e 00 65 00 78 00 65 00 } //00 00  ://185.215.113.93/pi.exe
	condition:
		any of ($a_*)
 
}