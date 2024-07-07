
rule Trojan_Win32_Trickbot_STS_dll{
	meta:
		description = "Trojan:Win32/Trickbot.STS!dll,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {fd ff ff d1 af d2 11 8b d9 c7 85 fc fd ff ff 9c b9 00 00 50 89 9d 08 fe ff ff c7 85 00 fe ff ff f8 7a 36 9e c7 85 e4 fd ff ff 7f 32 b6 50 c7 85 e8 fd ff ff d1 af d2 11 c7 85 ec fd ff ff 9c b9 00 00 c7 85 f0 fd ff ff f8 7a 36 9e } //1
		$a_01_1 = {c6 45 bd 71 c6 45 be 18 c6 45 bf 4f c6 45 c0 28 c6 45 c1 7a c6 45 c2 04 c6 45 c3 14 c6 45 c4 39 c6 45 c5 52 c6 45 c6 79 c6 45 c7 38 c6 45 c8 05 c6 45 c9 52 c6 45 ca 21 c6 45 cb 45 c6 45 cc 42 c6 45 cd 1b } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}