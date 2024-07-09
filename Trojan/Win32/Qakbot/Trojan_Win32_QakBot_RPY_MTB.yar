
rule Trojan_Win32_QakBot_RPY_MTB{
	meta:
		description = "Trojan:Win32/QakBot.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 80 f4 00 00 00 03 86 a4 00 00 00 2b c3 50 8b 46 34 33 c5 50 8b 86 ac 00 00 00 0d 34 1e 00 00 0f af 46 78 56 50 } //1
		$a_03_1 = {50 8b 46 64 33 44 24 2c 03 41 20 8d 8f 51 ff ff ff 50 69 c2 ?? ?? 00 00 50 8b c7 35 ?? ?? 00 00 05 ?? ?? 00 00 50 8b 86 ac 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}