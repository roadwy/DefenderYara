
rule Trojan_Win32_Gepys_PVS_MTB{
	meta:
		description = "Trojan:Win32/Gepys.PVS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {8b 45 f0 81 c3 47 86 c8 61 ff 4d ec 8b 4d f4 89 5d f8 0f 85 90 09 06 00 8b 15 90 00 } //2
		$a_02_1 = {29 c1 69 c1 13 91 03 00 a3 90 01 04 a1 90 01 04 09 d8 69 c0 af 5c 04 00 8d 73 01 a3 90 09 06 00 8b 0d 90 00 } //2
		$a_02_2 = {01 d8 05 a5 28 01 00 a3 90 01 04 a1 90 01 04 31 d8 05 71 25 04 00 a3 90 09 05 00 a1 90 00 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2+(#a_02_2  & 1)*2) >=2
 
}