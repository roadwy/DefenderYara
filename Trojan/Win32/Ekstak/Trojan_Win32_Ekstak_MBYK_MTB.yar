
rule Trojan_Win32_Ekstak_MBYK_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.MBYK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 6a ff 68 b8 f9 4b 00 68 38 9a 4b 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 e4 f3 4b 00 33 d2 8a d4 89 15 ?? 8d 4c 00 8b c8 } //2
		$a_01_1 = {55 8b ec 6a ff 68 b8 f9 4b 00 68 28 9a 4b 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 e4 f3 4b 00 33 d2 8a d4 89 15 60 8d 4c 00 8b c8 81 e1 ff 00 00 00 89 0d 5c 8d 4c 00 c1 e1 08 03 ca } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}