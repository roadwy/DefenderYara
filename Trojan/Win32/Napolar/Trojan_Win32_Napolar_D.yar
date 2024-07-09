
rule Trojan_Win32_Napolar_D{
	meta:
		description = "Trojan:Win32/Napolar.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {c1 ea 08 81 e2 ff ff ff 00 8b 34 b7 31 d6 89 f0 66 39 cb 77 ?? f7 d0 } //1
		$a_01_1 = {3d 4d 5a 00 00 75 2f 8b 73 3c 81 c6 f8 00 00 00 89 f0 c1 f8 1f bf 00 00 00 00 39 f8 } //1
		$a_01_2 = {30 3d 25 64 2e 25 64 26 31 3d 25 73 26 32 3d 25 73 26 33 3d 25 73 26 34 3d 25 64 2e 25 64 2e 25 64 26 35 3d 25 64 26 36 3d 25 73 } //1 0=%d.%d&1=%s&2=%s&3=%s&4=%d.%d.%d&5=%d&6=%s
		$a_01_3 = {5c 5c 2e 5c 70 69 70 65 5c 6e 70 78 38 36 5f 53 65 72 76 69 63 65 73 } //1 \\.\pipe\npx86_Services
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}