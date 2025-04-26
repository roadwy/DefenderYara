
rule Trojan_Win32_FakeAV_ASGT_MTB{
	meta:
		description = "Trojan:Win32/FakeAV.ASGT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 ec 10 56 57 68 ?? ?? ?? 00 6a 00 8d 44 24 14 6a 01 50 c7 44 24 1c 0c 00 00 00 c7 44 24 20 00 00 00 00 c7 44 24 24 00 00 00 00 ff 15 ?? ?? ?? 00 8b 0d ?? ?? ?? 00 8b f0 51 ff 15 ?? ?? ?? 00 8d 54 24 08 c7 44 24 08 00 00 00 00 } //3
		$a_03_1 = {55 8b ec 83 ec 10 53 56 57 a0 ?? ?? 66 00 32 05 ?? ?? 66 00 a2 ?? ?? 66 00 33 c9 8a 0d ?? ?? 66 00 c1 f9 03 83 c9 01 89 4d f0 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}