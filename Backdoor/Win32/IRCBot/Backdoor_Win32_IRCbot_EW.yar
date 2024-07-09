
rule Backdoor_Win32_IRCbot_EW{
	meta:
		description = "Backdoor:Win32/IRCbot.EW,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f8 3b 45 08 7d 21 e8 ?? ?? ?? 00 99 6a 0a 59 f7 f9 52 ff 75 fc } //1
		$a_00_1 = {25 73 5c 72 65 6d 6f 76 65 4d 65 25 69 25 69 25 69 25 69 2e 62 61 74 } //1 %s\removeMe%i%i%i%i.bat
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}