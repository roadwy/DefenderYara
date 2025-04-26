
rule Trojan_Win32_Danabot_OE_MTB{
	meta:
		description = "Trojan:Win32/Danabot.OE!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 57 ff 15 2c 80 40 00 eb 15 8b 45 fc 8d 34 03 e8 6f fe ff ff 30 06 b8 01 00 00 00 29 45 fc 39 7d fc 7d e6 5f 5e 5b c9 c3 } //1
		$a_01_1 = {53 65 74 50 72 6f 63 65 73 73 53 68 75 74 64 6f 77 6e 50 61 72 61 6d 65 74 65 72 73 } //1 SetProcessShutdownParameters
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}