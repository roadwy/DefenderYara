
rule Trojan_Win32_Trickbot_ASES_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.ASES!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b c1 c1 e8 18 33 c1 69 c8 91 e9 d1 5b 69 45 0c 91 e9 d1 5b 33 c8 89 4d 0c 3b 55 f8 0f } //1
		$a_01_1 = {5a 38 31 78 62 79 75 41 75 61 } //1 Z81xbyuAua
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}