
rule Trojan_Win32_Waldek_VU_MTB{
	meta:
		description = "Trojan:Win32/Waldek.VU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 55 d0 c1 e2 0b 89 55 d0 c6 45 ff 01 eb 42 c6 45 e7 01 c6 45 ef 01 8b 45 f8 c1 e0 dd 89 45 f8 c6 45 fe 01 8b 4d d0 81 f1 76 21 1b 00 89 4d d0 c6 45 cf 01 c6 45 e7 00 8b 55 f8 c1 fa 2b 89 55 f8 c6 45 ff 01 c6 45 ef 01 } //10
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}