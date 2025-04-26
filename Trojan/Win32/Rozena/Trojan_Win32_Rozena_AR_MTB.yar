
rule Trojan_Win32_Rozena_AR_MTB{
	meta:
		description = "Trojan:Win32/Rozena.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {01 d0 0f b6 10 8d 8d [0-04] 8b 45 d4 01 c8 0f b6 00 31 c2 8d 8d [0-04] 8b 45 d0 01 c8 88 10 } //2
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}