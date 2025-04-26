
rule Trojan_Win32_FakeAV_AFK_MTB{
	meta:
		description = "Trojan:Win32/FakeAV.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {c6 85 7c ff ff ff 00 8b 55 fc 89 95 78 ff ff ff 8b 85 78 ff ff ff 03 45 8c 8a 08 88 8d 7c ff ff ff 8a 95 7c ff ff ff 02 55 c0 88 95 7c ff ff ff 6a 01 8d 85 7c ff ff ff 50 8b 8d 78 ff ff ff 03 4d 8c 51 } //1
		$a_01_1 = {8b 4d f4 89 4d a8 8b 55 c8 83 c2 01 89 55 c8 8b 45 c8 6b c0 03 89 45 b8 8b 4d a8 89 4d c4 8b 55 c4 03 55 ac 89 55 c4 8b 45 a0 50 8b 4d a8 03 4d ac 51 8b 55 fc 52 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}