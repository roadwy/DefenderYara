
rule Trojan_Win32_Vidar_AVDR_MTB{
	meta:
		description = "Trojan:Win32/Vidar.AVDR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 34 3b 8a 04 30 88 45 ff ff 15 ?? ?? ?? ?? 8b c8 33 d2 8b c3 f7 f1 8b 45 0c 8a 04 02 32 45 ff 43 88 06 } //2
		$a_03_1 = {8b c8 83 e1 03 8a 8c 0d ?? ?? ?? ?? 30 0c 06 40 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}