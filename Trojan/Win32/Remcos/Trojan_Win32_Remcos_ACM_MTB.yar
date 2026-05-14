
rule Trojan_Win32_Remcos_ACM_MTB{
	meta:
		description = "Trojan:Win32/Remcos.ACM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 44 24 08 50 8d 44 24 1c 50 68 28 04 00 00 8d 44 24 0c 50 ff 15 ?? ?? ?? ?? 68 ?? 15 46 00 68 ?? 15 46 00 e8 } //2
		$a_01_1 = {c6 44 24 10 b8 c6 44 24 11 01 c6 44 24 12 00 c6 44 24 13 00 c6 44 24 14 00 c6 44 24 15 c3 8d 44 24 04 50 6a 06 8d 44 24 18 50 56 8b 44 24 10 50 ff 15 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}