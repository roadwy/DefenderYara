
rule Trojan_Win32_Qakbot_BR_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.BR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 55 d0 0f be 02 89 85 d8 fe ff ff 8b 4d 8c 33 8d d8 fe ff ff 89 4d 8c 8b 55 d0 83 c2 01 89 55 d0 33 c0 74 09 8b 4d d0 83 c1 01 89 4d d0 eb } //1
		$a_01_1 = {03 72 14 8b 85 70 ff ff ff 8b 7d f4 03 78 0c 8b 49 10 f3 a4 8b 8d 70 ff ff ff 83 c1 28 89 8d 70 ff ff ff eb } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}