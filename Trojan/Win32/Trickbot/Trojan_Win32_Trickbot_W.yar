
rule Trojan_Win32_Trickbot_W{
	meta:
		description = "Trojan:Win32/Trickbot.W,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {45 6c 64 2e 32 33 6c 65 6e 72 65 4b } //1 Eld.23lenreK
		$a_01_1 = {41 74 78 65 74 6e 6f 43 65 72 69 75 71 63 41 74 70 79 72 43 } //1 AtxetnoCeriuqcAtpyrC
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}