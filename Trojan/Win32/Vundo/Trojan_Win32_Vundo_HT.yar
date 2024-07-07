
rule Trojan_Win32_Vundo_HT{
	meta:
		description = "Trojan:Win32/Vundo.HT,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff 75 08 59 ff 75 fc 5a 8b 14 97 90 01 02 e8 90 01 04 39 45 0c 0f 84 10 00 00 00 ff 45 fc ff 75 fc 58 3b 46 18 0f 82 d5 ff ff ff ff 75 fc 5a ff 75 08 59 ff 75 f4 58 3b 56 18 0f 90 01 05 0f b7 04 50 8b 1c 83 ff 75 f8 58 90 01 04 3b d8 89 5d 0c 90 00 } //1
		$a_03_1 = {ff 75 08 59 ff 75 fc 5a 8b 14 97 90 01 02 e8 90 01 04 39 45 0c 0f 84 10 00 00 00 ff 45 fc ff 75 fc 58 3b 46 18 0f 82 d5 ff ff ff 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}