
rule Trojan_Win32_Foreign_GVA_MTB{
	meta:
		description = "Trojan:Win32/Foreign.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 c2 04 03 80 f2 1b 88 94 0c 5a 01 00 00 41 83 f9 1e 74 18 0f b6 94 0c 5a 01 00 00 89 ce 83 e6 03 74 dd 83 fe 02 75 dc 28 c2 eb d8 } //2
		$a_01_1 = {00 df 0f b6 c7 0f b6 84 04 78 01 00 00 30 44 2f 40 45 74 b7 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}