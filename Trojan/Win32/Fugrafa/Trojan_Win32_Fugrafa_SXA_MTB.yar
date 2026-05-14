
rule Trojan_Win32_Fugrafa_SXA_MTB{
	meta:
		description = "Trojan:Win32/Fugrafa.SXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 4d 88 8b 55 8c 8b 45 84 03 4d 80 13 d0 83 c1 01 83 d2 00 89 8d 60 ff ff ff 89 95 64 ff ff ff } //20
		$a_01_1 = {0f 28 45 e0 0f 29 85 10 ff ff ff 8b 4d c8 0f 10 01 0f 29 85 20 ff ff ff 0f 28 85 20 ff ff ff 66 0f ef 85 10 ff ff ff 0f 29 85 00 ff ff ff 0f 28 85 00 ff ff ff 8b 55 c8 0f 11 02 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}