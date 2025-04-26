
rule Trojan_Win32_Qukart_ASCA_MTB{
	meta:
		description = "Trojan:Win32/Qukart.ASCA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {89 e5 51 50 56 57 bf 6f 26 9e 39 89 f8 01 f8 89 c7 8d 45 fc 50 68 19 00 02 00 6a 00 ff 75 0c ff 75 08 e8 } //2
		$a_01_1 = {89 e5 51 50 56 57 bf 5e 3a fc 78 89 f8 31 f8 89 c7 8d 45 f8 50 8d 45 fc 50 6a 00 68 3f 00 0f 00 6a 00 6a 00 6a 00 ff 75 0c ff 75 08 e8 } //2
		$a_01_2 = {53 56 57 8b 75 0c 8b 5d 10 c7 85 fc ff fe ff b7 4b 62 37 8b 85 fc ff fe ff 89 c2 31 c2 89 95 } //2
		$a_01_3 = {e5 83 ec 0c 53 56 57 8b 75 0c bb fb 52 a9 66 89 d8 31 d8 89 c3 ff 05 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=4
 
}