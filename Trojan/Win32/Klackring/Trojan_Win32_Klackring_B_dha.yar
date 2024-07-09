
rule Trojan_Win32_Klackring_B_dha{
	meta:
		description = "Trojan:Win32/Klackring.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {62 aa a2 b2 c7 ?? ?? c9 f4 f0 c6 c7 ?? ?? 62 b1 f2 e3 c7 ?? ?? 16 ae 6f 9c } //1
		$a_03_1 = {6b 49 a3 8d c7 ?? ?? d8 dd 21 2b c7 ?? ?? 38 59 bb bf c7 ?? ?? 06 c0 33 c2 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}