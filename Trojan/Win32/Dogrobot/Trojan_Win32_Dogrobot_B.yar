
rule Trojan_Win32_Dogrobot_B{
	meta:
		description = "Trojan:Win32/Dogrobot.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 e1 03 50 68 10 30 00 10 6a 67 f3 a4 e8 ?? ?? ff ff } //1
		$a_01_1 = {5c 64 72 69 76 65 72 73 5c 52 45 53 53 44 54 2e 73 79 73 } //1 \drivers\RESSDT.sys
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}