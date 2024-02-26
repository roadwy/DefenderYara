
rule Trojan_Win32_Zbot_FFH_MTB{
	meta:
		description = "Trojan:Win32/Zbot.FFH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8b 44 24 10 8b 14 85 90 01 04 33 c0 8b cf 40 c1 e9 02 3b c8 76 08 31 14 83 40 3b c1 72 f8 90 00 } //01 00 
		$a_80_1 = {65 76 65 64 62 6f 6e 6c 69 6e 65 2e 63 6f 6d } //evedbonline.com  01 00 
		$a_80_2 = {61 6c 61 6d 78 2e 63 6f 6d } //alamx.com  01 00 
		$a_80_3 = {67 66 66 6f 73 2e 65 78 65 } //gffos.exe  01 00 
		$a_80_4 = {72 6f 70 65 72 6e 73 2e 65 78 65 } //roperns.exe  00 00 
	condition:
		any of ($a_*)
 
}