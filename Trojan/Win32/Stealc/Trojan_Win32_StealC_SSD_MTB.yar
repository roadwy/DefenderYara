
rule Trojan_Win32_StealC_SSD_MTB{
	meta:
		description = "Trojan:Win32/StealC.SSD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c9 c6 45 ?? 00 8d 45 dd 30 14 08 41 83 f9 0b 73 } //1
		$a_03_1 = {0f b6 c0 33 94 85 b8 f7 ff ff 0f b6 c1 03 94 85 b8 fb ff ff 8b 85 ?? ?? ?? ?? 33 14 38 83 ad 5c ef ff ff 01 89 14 38 8b 85 68 ef ff ff 8b 0c 07 89 14 07 8b d0 89 4c 38 04 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}