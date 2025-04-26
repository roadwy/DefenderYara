
rule Trojan_Win32_Lamechi_C{
	meta:
		description = "Trojan:Win32/Lamechi.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {b9 aa aa aa aa 39 8c 04 ?? ?? ?? ?? 74 0a 40 3d 00 02 00 00 72 ef eb 0d 8d 96 00 08 00 00 } //1
		$a_01_1 = {c7 00 4e 56 53 2e c7 40 08 00 00 00 00 c7 40 04 05 00 00 00 c7 40 0c 00 00 00 00 c7 40 10 10 27 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}