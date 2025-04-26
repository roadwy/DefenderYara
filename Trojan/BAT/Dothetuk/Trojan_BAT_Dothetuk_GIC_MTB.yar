
rule Trojan_BAT_Dothetuk_GIC_MTB{
	meta:
		description = "Trojan:BAT/Dothetuk.GIC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 67 00 00 70 28 ?? ?? ?? 06 0b 28 ?? ?? ?? 0a 07 6f ?? ?? ?? 0a 72 e5 00 00 70 7e 1c 00 00 0a 6f 1d 00 00 0a 28 ?? ?? ?? 0a 0c de 17 26 20 d0 07 00 00 28 ?? ?? ?? 0a de 00 06 17 58 0a 06 1b 32 bd } //10
		$a_80_1 = {61 6f 63 67 61 6d 65 73 74 75 64 69 6f 2e 78 79 7a } //aocgamestudio.xyz  1
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}