
rule Trojan_Win32_KillWin_ARAZ_MTB{
	meta:
		description = "Trojan:Win32/KillWin.ARAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 55 f0 8b 04 b2 46 89 04 24 e8 81 4a 00 00 01 c7 39 de 7c eb } //2
		$a_01_1 = {5c 42 32 45 2e 74 6d 70 } //2 \B2E.tmp
		$a_01_2 = {41 64 64 41 74 6f 6d 41 } //1 AddAtomA
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}