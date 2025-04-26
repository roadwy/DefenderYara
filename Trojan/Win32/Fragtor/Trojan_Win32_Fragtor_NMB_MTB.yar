
rule Trojan_Win32_Fragtor_NMB_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.NMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 c5 89 45 fc 33 c0 66 c7 45 e8 61 6e 66 89 45 de } //1
		$a_03_1 = {83 c4 18 84 c0 0f 94 c0 20 05 ?? ?? ?? ?? 8b 85 64 f5 ff ff 83 f8 08 72 13 40 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}