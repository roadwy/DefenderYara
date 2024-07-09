
rule Trojan_Win32_TrickBot_PDSK_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.PDSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 75 fc 09 10 a1 ?? ?? ?? ?? 8b 00 89 01 66 a1 ?? ?? ?? ?? 66 83 c0 fa 66 a3 90 09 0b 00 a1 ?? ?? ?? ?? 8b 0d } //2
		$a_00_1 = {8b 06 01 d8 8b 55 e4 30 10 43 8b 06 3b 58 f4 72 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*2) >=2
 
}