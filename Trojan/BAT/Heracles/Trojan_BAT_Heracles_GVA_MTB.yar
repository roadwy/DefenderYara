
rule Trojan_BAT_Heracles_GVA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_02_0 = {02 18 5d 2c 04 02 ?? ?? 2a 02 18 58 2a } //2
		$a_01_1 = {02 18 5d 2c 04 02 18 5a 2a 02 18 5b 2a } //2
		$a_01_2 = {02 03 5a 03 2c 03 03 2b 01 17 5b 2a } //2 ͚̬̂⬃ᜁ⩛
		$a_02_3 = {03 17 31 0d 03 6a 02 03 17 59 28 ?? ?? ?? ?? 5a 2a 17 6a 2a } //2
	condition:
		((#a_02_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_02_3  & 1)*2) >=2
 
}