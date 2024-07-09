
rule Trojan_Win32_Serubsit_A{
	meta:
		description = "Trojan:Win32/Serubsit.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {8a 0a 42 80 7c 24 10 00 75 0b 8d 59 9f 80 fb 19 77 03 80 c1 e0 0f b6 f0 0f b6 c9 33 f1 c1 e8 08 33 } //1
		$a_03_1 = {66 83 7d ac 63 90 13 66 83 7d ac 66 90 13 66 83 7d ac 23 90 13 6a 7b 58 66 89 07 } //1
		$a_01_2 = {ff 51 10 85 c0 78 4c 8b 45 fc 8b 08 50 ff 51 1c 85 c0 78 36 33 ff eb 1f } //1
		$a_01_3 = {3f 77 3d 7b 75 73 65 72 7d 26 73 3d 7b 73 75 62 64 7d 26 73 69 74 65 5f 69 64 3d 7b 73 69 74 65 7d } //1 ?w={user}&s={subd}&site_id={site}
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}