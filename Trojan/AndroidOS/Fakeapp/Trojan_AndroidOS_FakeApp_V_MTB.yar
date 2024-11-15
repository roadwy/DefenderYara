
rule Trojan_AndroidOS_FakeApp_V_MTB{
	meta:
		description = "Trojan:AndroidOS/FakeApp.V!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {54 65 6c 65 67 72 61 6d 2f 56 69 50 2f 54 65 6c 65 67 72 61 6d 41 63 74 69 76 69 74 79 } //1 Telegram/ViP/TelegramActivity
		$a_01_1 = {5f 49 43 6f 6e 73 50 6f 68 65 6e 52 41 54 } //1 _IConsPohenRAT
		$a_01_2 = {42 4f 54 5f 54 4f 4b 45 4e } //1 BOT_TOKEN
		$a_01_3 = {42 6c 6f 63 6b 5f 55 65 73 61 72 6e 61 6d 65 } //1 Block_Uesarname
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}