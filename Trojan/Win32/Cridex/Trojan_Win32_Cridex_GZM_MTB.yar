
rule Trojan_Win32_Cridex_GZM_MTB{
	meta:
		description = "Trojan:Win32/Cridex.GZM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_02_0 = {8b 01 ba ff fe fe 7e 03 d0 83 f0 ?? 33 c2 83 c1 ?? a9 ?? ?? ?? ?? 74 e8 } //10
		$a_01_1 = {62 65 73 74 68 6f 74 65 6c 33 36 30 2e 63 6f 6d } //1 besthotel360.com
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_3 = {6c 43 51 68 41 6d 61 6c 43 51 68 41 6d 61 6c 43 51 68 41 6d 61 } //1 lCQhAmalCQhAmalCQhAma
	condition:
		((#a_02_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=13
 
}