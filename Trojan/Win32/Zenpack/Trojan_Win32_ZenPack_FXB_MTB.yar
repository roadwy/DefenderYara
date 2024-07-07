
rule Trojan_Win32_ZenPack_FXB_MTB{
	meta:
		description = "Trojan:Win32/ZenPack.FXB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f be d1 80 e9 41 8b c2 83 c8 20 80 f9 19 8a 0b 0f 47 c2 33 c6 69 f0 a1 01 00 01 43 84 c9 75 e0 } //10
		$a_01_1 = {4c 6f 61 64 4c 69 62 72 61 72 79 43 } //1 LoadLibraryC
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}