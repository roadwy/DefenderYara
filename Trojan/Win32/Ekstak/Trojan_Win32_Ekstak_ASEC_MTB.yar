
rule Trojan_Win32_Ekstak_ASEC_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASEC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 4c 24 0c 8d 54 24 08 51 68 ?? ?? 4c 00 52 50 89 44 24 18 50 8b 44 24 18 c7 44 24 20 08 02 00 00 50 ff 15 ?? ?? 4c 00 85 c0 a3 } //4
		$a_03_1 = {81 ec bc 00 00 00 8d 44 24 00 56 57 50 ff 15 ?? ?? 65 00 68 4c 30 65 00 6a 00 68 01 00 1f 00 ff 15 ?? ?? 65 00 85 c0 74 } //4
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*4) >=4
 
}