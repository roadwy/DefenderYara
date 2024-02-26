
rule Trojan_Win32_Bobik_NB_MTB{
	meta:
		description = "Trojan:Win32/Bobik.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {64 89 20 8d 55 fc 8b c3 e8 7e 67 00 00 8b c7 8b ce 8b 55 90 01 01 e8 c6 0d 00 00 33 c0 5a 59 59 64 89 10 68 65 9f 90 00 } //01 00 
		$a_01_1 = {57 57 41 4e 5f 41 75 74 6f 43 6f 6e 66 69 67 2e 65 78 65 } //00 00  WWAN_AutoConfig.exe
	condition:
		any of ($a_*)
 
}