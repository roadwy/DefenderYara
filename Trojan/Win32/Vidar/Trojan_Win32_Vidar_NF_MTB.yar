
rule Trojan_Win32_Vidar_NF_MTB{
	meta:
		description = "Trojan:Win32/Vidar.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 89 e5 57 56 83 ec 2c a1 ?? ?? ?? ?? 8b 7d 0c 8d 75 dc 31 e8 89 45 f4 b8 be 78 b2 ed 3d e3 0b 35 19 7e 13 eb 5a 84 c9 0f 45 c2 } //2
		$a_01_1 = {83 e1 1f 8b 7e 04 33 d8 8b 76 08 33 f8 33 f0 d3 cf d3 ce d3 cb 3b fe 75 7b 2b f3 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}