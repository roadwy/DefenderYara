
rule Trojan_Win32_Klackring_B_dha{
	meta:
		description = "Trojan:Win32/Klackring.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {62 aa a2 b2 c7 90 01 02 c9 f4 f0 c6 c7 90 01 02 62 b1 f2 e3 c7 90 01 02 16 ae 6f 9c 90 00 } //01 00 
		$a_03_1 = {6b 49 a3 8d c7 90 01 02 d8 dd 21 2b c7 90 01 02 38 59 bb bf c7 90 01 02 06 c0 33 c2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}