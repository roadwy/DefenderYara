
rule Trojan_Win32_Zusy_LMF_MTB{
	meta:
		description = "Trojan:Win32/Zusy.LMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_03_0 = {33 c0 8b 55 ec 01 13 8b 75 d4 03 75 a4 03 75 ec 03 f0 bf 89 15 00 00 6a 00 e8 ?? ?? ?? ?? 03 fe 81 ef 89 15 00 00 2b f8 6a 00 e8 ?? ?? ?? ?? 2b f8 31 3b 83 45 ec 04 83 c3 04 8b 45 ec 3b 45 dc } //20
		$a_01_1 = {40 00 50 d2 40 00 d0 d0 40 00 bc da 40 00 8c da 40 00 34 35 41 00 bc 34 41 00 f8 36 41 00 c8 36 41 00 e0 3e 41 00 90 3e 41 00 78 d6 41 00 c8 d5 41 00 60 4c 42 00 30 4c } //10
		$a_03_2 = {ff 45 ec 81 7d ec 2c 8c 74 15 75 ?? c7 45 a4 8a a5 08 00 bb e3 14 00 00 c7 45 c4 9f 0a 00 00 89 65 fc 81 45 fc 64 02 00 00 89 6d f8 81 45 f8 c0 01 00 00 8d 0d 68 56 45 00 8b 41 f0 89 45 f4 8b 41 ec 89 45 f0 c7 45 d8 c0 70 2c 00 } //5
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*10+(#a_03_2  & 1)*5) >=35
 
}