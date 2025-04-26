
rule Trojan_Win32_Farfli_AY_MTB{
	meta:
		description = "Trojan:Win32/Farfli.AY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 8d 0c 02 0f b7 c6 8a 44 45 ec 30 01 46 42 3b d7 72 e3 } //2
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //2 VirtualAlloc
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}