
rule Ransom_Win32_KeyPass_MAK_MTB{
	meta:
		description = "Ransom:Win32/KeyPass.MAK!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 b0 58 5c 63 00 8b d6 8b ce c1 ea 07 69 fa 00 00 00 1b c1 e1 19 69 d2 1b 01 00 00 33 f9 8b ce c1 e1 08 0b ce c1 e1 08 0b f9 8d 0c 36 33 d1 33 c9 33 d6 0b cf 0b d7 89 0c c5 50 8e 68 00 89 14 c5 54 8e 68 00 40 3d 00 01 00 00 7c b2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}