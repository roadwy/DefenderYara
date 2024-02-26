
rule Trojan_Win32_Lazy_NL_MTB{
	meta:
		description = "Trojan:Win32/Lazy.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {66 77 65 68 66 77 65 6f 6a 6f 69 72 } //02 00  fwehfweojoir
		$a_01_1 = {70 72 65 73 69 64 65 6e 74 73 74 61 74 69 73 74 69 63 70 72 6f } //02 00  presidentstatisticpro
		$a_01_2 = {4b 55 51 34 50 77 6f 58 62 67 2e 65 78 65 } //00 00  KUQ4PwoXbg.exe
	condition:
		any of ($a_*)
 
}