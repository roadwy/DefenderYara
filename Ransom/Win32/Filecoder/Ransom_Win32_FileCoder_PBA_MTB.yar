
rule Ransom_Win32_FileCoder_PBA_MTB{
	meta:
		description = "Ransom:Win32/FileCoder.PBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 81 d1 af 45 66 ba 1c 0b 2d 19 22 00 00 02 2d ?? ?? ?? ?? 81 f2 ?? ?? ?? ?? 89 d1 c1 e2 ?? 8b 44 24 ?? 0f b7 c9 ba 0b 72 00 00 81 f1 9e 4e 00 00 31 58 ?? 68 03 6e ff ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}