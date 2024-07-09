
rule Trojan_Win32_PikaBot_CCET_MTB{
	meta:
		description = "Trojan:Win32/PikaBot.CCET!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 55 f0 0f b6 82 ?? ?? ?? ?? 8b 4d f0 81 e1 } //1
		$a_01_1 = {33 c2 8b 4d fc 03 4d f0 88 01 } //1
		$a_01_2 = {8b 45 f0 83 c0 01 89 45 f0 8b 4d f0 3b 4d f4 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}