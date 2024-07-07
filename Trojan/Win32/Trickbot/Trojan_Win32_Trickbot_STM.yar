
rule Trojan_Win32_Trickbot_STM{
	meta:
		description = "Trojan:Win32/Trickbot.STM,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {4d 61 69 6c 43 6c 69 65 6e 74 2e 64 6c 6c } //MailClient.dll  1
		$a_80_1 = {43 6f 6e 74 72 6f 6c 00 46 72 65 65 42 75 66 66 65 72 } //Control  1
		$a_80_2 = {49 6e 6a 65 63 74 65 64 20 70 72 6f 63 65 73 73 20 70 69 64 } //Injected process pid  1
		$a_80_3 = {57 65 62 49 6e 6a 65 63 74 20 62 75 69 6c 64 } //WebInject build  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}