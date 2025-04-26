
rule Trojan_Win32_Pikabot_ZU_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.ZU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {03 c3 89 45 f0 eb 3d } //1
		$a_03_1 = {8b 45 f0 33 d2 eb 00 b9 ?? ?? ?? ?? 83 c1 25 eb db 69 45 f0 ?? ?? ?? ?? bb 39 30 00 00 eb c6 b9 db 7f 00 00 83 c1 25 eb ca 8b 45 f0 33 d2 eb ef 48 89 45 ec e9 58 ff ff ff e9 } //1
		$a_01_2 = {45 78 63 70 74 } //1 Excpt
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}