
rule Backdoor_Win32_IRCbot_GQ{
	meta:
		description = "Backdoor:Win32/IRCbot.GQ,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0b 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 74 61 72 74 69 6e 67 20 49 52 43 20 54 68 72 65 61 64 } //5 Starting IRC Thread
		$a_01_1 = {49 6e 6a 65 63 74 65 64 20 66 6f 72 6d 67 72 61 62 62 65 72 } //5 Injected formgrabber
		$a_01_2 = {64 75 6d 62 61 73 73 2e 62 6f 61 74 6e 65 74 2e 72 75 } //1 dumbass.boatnet.ru
		$a_01_3 = {2e 00 70 00 61 00 79 00 70 00 61 00 6c 00 } //1 .paypal
		$a_01_4 = {6c 00 6f 00 67 00 69 00 6e 00 5f 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 3d 00 } //1 login_password=
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=11
 
}