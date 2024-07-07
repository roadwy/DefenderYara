
rule Trojan_Win32_Zbot_DAO_MTB{
	meta:
		description = "Trojan:Win32/Zbot.DAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {48 24 6d 48 bf 33 6d b9 65 a1 d5 47 33 10 08 33 32 33 bf 48 bf a1 89 6d 48 08 b9 bf 33 47 a5 0f 24 d5 a5 e6 a1 10 6d 10 32 10 32 a5 a5 24 6d 33 b9 47 6d } //1
		$a_01_1 = {54 37 61 6d 35 79 48 4d 61 4c 65 37 6f 50 4a 45 6d 73 6e 6e 50 58 4c 56 37 6c 49 42 6a 53 67 67 61 6d 6e 4a 49 36 4b 6e 73 48 50 74 38 61 } //1 T7am5yHMaLe7oPJEmsnnPXLV7lIBjSggamnJI6KnsHPt8a
		$a_01_2 = {46 34 4f 74 63 6e 46 45 50 4e 69 70 64 59 75 35 47 52 42 31 4c 69 35 66 72 53 73 41 31 41 36 67 6e 6d 56 43 64 57 56 53 46 75 77 72 62 31 55 57 62 69 75 4c 38 56 } //1 F4OtcnFEPNipdYu5GRB1Li5frSsA1A6gnmVCdWVSFuwrb1UWbiuL8V
		$a_01_3 = {78 45 38 4c 6a 6e 4a 72 69 36 72 4c 6c 61 76 69 43 4a 55 76 36 47 58 6e 65 4b 65 6f 55 68 61 67 56 65 75 65 44 4c 78 56 33 65 45 44 61 65 4e 71 57 38 37 34 62 } //1 xE8LjnJri6rLlaviCJUv6GXneKeoUhagVeueDLxV3eEDaeNqW874b
		$a_01_4 = {6e 65 77 69 61 74 } //1 newiat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}