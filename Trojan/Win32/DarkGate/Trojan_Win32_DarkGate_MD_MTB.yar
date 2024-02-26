
rule Trojan_Win32_DarkGate_MD_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {2d 2d 48 45 49 4c 20 48 49 54 4c 45 52 2d 2d } //01 00  --HEIL HITLER--
		$a_01_1 = {64 61 72 6b 6c 6f 61 64 65 72 } //01 00  darkloader
		$a_01_2 = {74 00 70 00 3a 00 2f 00 2f 00 64 00 61 00 72 00 6b 00 6c 00 6f 00 61 00 64 00 65 00 72 00 2e 00 74 00 6f 00 70 00 2f 00 } //01 00  tp://darkloader.top/
		$a_01_3 = {74 00 70 00 3a 00 2f 00 2f 00 63 00 6c 00 6f 00 73 00 65 00 68 00 75 00 62 00 2e 00 72 00 75 00 2f 00 } //01 00  tp://closehub.ru/
		$a_01_4 = {41 00 6e 00 74 00 69 00 53 00 74 00 65 00 61 00 6c 00 65 00 72 00 42 00 79 00 44 00 61 00 72 00 6b 00 50 00 31 00 78 00 65 00 6c 00 } //00 00  AntiStealerByDarkP1xel
	condition:
		any of ($a_*)
 
}