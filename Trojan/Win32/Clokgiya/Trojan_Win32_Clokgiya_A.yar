
rule Trojan_Win32_Clokgiya_A{
	meta:
		description = "Trojan:Win32/Clokgiya.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c0 b1 61 8b d0 81 e2 01 00 00 80 79 05 4a 83 ca fe 42 75 06 30 88 ?? ?? 40 00 } //1
		$a_01_1 = {34 e9 b2 00 61 00 3e 8b 8e e8 d5 00 61 00 ea fd 36 06 6e a0 66 26 c0 30 61 00 61 07 ea 40 6d 8b } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}