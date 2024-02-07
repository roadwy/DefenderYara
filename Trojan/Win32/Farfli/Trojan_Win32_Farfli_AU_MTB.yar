
rule Trojan_Win32_Farfli_AU_MTB{
	meta:
		description = "Trojan:Win32/Farfli.AU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {44 1f 9c 32 55 a4 42 31 b7 90 02 04 77 f6 90 00 } //02 00 
		$a_01_1 = {49 28 db 31 67 f4 6a 0d fc 09 3f } //01 00 
		$a_01_2 = {25 73 2e 65 78 65 } //00 00  %s.exe
	condition:
		any of ($a_*)
 
}