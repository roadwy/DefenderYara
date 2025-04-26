
rule Trojan_Win32_Pramro_B{
	meta:
		description = "Trojan:Win32/Pramro.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {f7 f9 81 c2 9b 04 00 00 89 95 ?? ?? ff ff 66 8b 95 ?? ?? ff ff 52 ff 15 90 09 06 00 99 b9 (10 27|40 1f) 00 00 } //2
		$a_03_1 = {c7 85 d4 ef ff ff f4 01 00 00 0f be ?? d1 df ff ff 83 ?? 02 89 ?? d0 ef ff ff eb 05 e9 } //2
		$a_01_2 = {4e 45 54 53 44 } //1 NETSD
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=3
 
}