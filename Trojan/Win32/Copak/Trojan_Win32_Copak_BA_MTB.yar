
rule Trojan_Win32_Copak_BA_MTB{
	meta:
		description = "Trojan:Win32/Copak.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {31 38 09 c9 09 c9 81 c0 04 00 00 00 49 81 c2 01 00 00 00 39 d8 75 e4 } //02 00 
		$a_01_1 = {01 db 40 bb 60 80 d6 30 01 f3 81 f8 e1 a4 00 01 75 9a } //00 00 
	condition:
		any of ($a_*)
 
}