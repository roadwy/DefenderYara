
rule Trojan_Win32_Sinowal_gen_B{
	meta:
		description = "Trojan:Win32/Sinowal.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_03_0 = {81 3a 50 45 00 00 74 04 32 c0 eb ?? 8b 45 f0 83 c0 04 89 45 f0 8b 4d f0 83 c1 14 89 4d f8 8b 55 f8 0f b7 02 3d 0b 01 00 00 74 } //5
		$a_03_1 = {83 ec 44 c7 45 fc ff ff ff ff c7 45 bc 00 00 00 00 90 13 83 7d bc ?? 73 } //1
		$a_01_2 = {c7 45 bc 00 00 00 00 eb 09 8b 4d bc 83 c1 01 } //1
		$a_01_3 = {8b 45 bc 83 c0 01 89 45 bc } //1
		$a_01_4 = {8b 45 fc 0f af 45 fc 83 c0 64 } //1
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}