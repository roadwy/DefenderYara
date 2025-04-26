
rule Trojan_Win32_Zbot_A_MTB{
	meta:
		description = "Trojan:Win32/Zbot.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6a 00 c1 da 05 33 dd 33 ff bf 2a 23 39 8c ff 75 bc c1 ca 0a b9 fe 4e f7 e0 c1 de 03 ff 15 6c d1 40 00 83 c4 04 c1 c2 01 89 d9 bb b6 54 1e 34 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zbot_A_MTB_2{
	meta:
		description = "Trojan:Win32/Zbot.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {43 61 72 57 6f 72 6b 65 72 2e 65 78 } //1 CarWorker.ex
		$a_01_1 = {68 00 67 00 6b 00 79 00 74 00 69 00 79 00 67 00 6b 00 68 00 76 00 6d 00 6e 00 62 00 76 00 66 00 6a 00 68 00 67 00 66 00 75 00 79 00 65 00 72 00 65 00 64 00 67 00 66 00 64 00 68 00 67 00 6b 00 6a 00 68 00 67 00 6b 00 68 00 67 00 6a 00 67 00 66 00 68 00 64 00 79 00 72 00 65 00 74 00 72 00 66 00 64 00 63 00 62 00 76 00 63 00 6e 00 76 00 63 00 6e 00 } //1 hgkytiygkhvmnbvfjhgfuyeredgfdhgkjhgkhgjgfhdyretrfdcbvcnvcn
		$a_01_2 = {52 00 6f 00 61 00 64 00 53 00 69 00 64 00 65 00 72 00 4d 00 6f 00 75 00 6e 00 74 00 } //1 RoadSiderMount
	condition:
		((#a_81_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}