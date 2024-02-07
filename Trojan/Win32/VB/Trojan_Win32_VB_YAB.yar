
rule Trojan_Win32_VB_YAB{
	meta:
		description = "Trojan:Win32/VB.YAB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 00 48 00 69 00 6a 00 61 00 63 00 6b 00 2e 00 65 00 78 00 65 00 } //01 00  \Hijack.exe
		$a_01_1 = {6e 00 52 00 65 00 73 00 75 00 72 00 72 00 65 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 62 00 61 00 74 00 } //01 00  nResurrection.bat
		$a_01_2 = {2e 00 31 00 38 00 32 00 38 00 36 00 2e 00 6e 00 65 00 74 00 2f 00 3f 00 78 00 69 00 6e 00 } //01 00  .18286.net/?xin
		$a_01_3 = {4e 00 61 00 4e 00 69 00 61 00 6e 00 48 00 75 00 61 00 4b 00 61 00 69 00 } //00 00  NaNianHuaKai
	condition:
		any of ($a_*)
 
}