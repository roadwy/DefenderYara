
rule Trojan_Win32_Pikabot_PC_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_03_1 = {42 0f b6 d2 8a 84 15 [0-04] 01 c1 0f b6 c9 8a 9c 0d [0-04] 88 9c 15 [0-04] 88 84 0d [0-04] 02 84 15 [0-04] 0f b6 c0 8a 84 05 [0-04] 32 84 2e [0-04] 0f b6 c0 66 89 84 75 [0-04] 46 83 fe ?? 75 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*10) >=11
 
}