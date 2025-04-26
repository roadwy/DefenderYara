
rule Trojan_Win32_Zbot_AZT_MTB{
	meta:
		description = "Trojan:Win32/Zbot.AZT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {23 02 20 68 25 20 02 20 68 1d 20 02 20 68 15 20 02 20 e9 0d ee ff ff 32 9c 68 ?? ?? ?? ?? 68 25 20 02 20 68 1d 20 02 20 68 15 20 02 20 } //3
		$a_01_1 = {d0 8b d8 c3 a1 8b 73 3c c3 8f 03 f3 c3 aa 8b 86 80 00 00 00 c3 f3 fd 8b 44 18 10 c3 41 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}