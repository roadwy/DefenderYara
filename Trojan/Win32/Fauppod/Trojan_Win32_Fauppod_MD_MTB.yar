
rule Trojan_Win32_Fauppod_MD_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {59 66 63 76 79 67 46 66 74 76 79 67 } //02 00  YfcvygFftvyg
		$a_01_1 = {59 76 79 67 62 68 4a 68 62 75 67 } //02 00  YvygbhJhbug
		$a_01_2 = {4f 75 6e 54 76 66 67 } //01 00  OunTvfg
		$a_01_3 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 45 78 } //00 00  WaitForSingleObjectEx
	condition:
		any of ($a_*)
 
}