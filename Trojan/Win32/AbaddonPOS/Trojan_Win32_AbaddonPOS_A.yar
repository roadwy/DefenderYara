
rule Trojan_Win32_AbaddonPOS_A{
	meta:
		description = "Trojan:Win32/AbaddonPOS.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {80 39 30 72 ?? 80 39 39 [0-0f] 80 39 5e [0-04] 80 39 3d } //1
		$a_01_1 = {31 0b 81 3b 55 89 e5 8b 74 0e 83 f8 00 75 09 31 0b 29 c3 31 c0 41 } //1
		$a_01_2 = {81 be a0 01 00 00 00 f4 01 00 74 24 81 be a0 01 00 00 00 e8 03 00 74 18 81 be a0 01 00 00 00 dc 05 00 74 0c 81 be a0 01 00 00 00 d6 06 00 75 08 6a 05 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}