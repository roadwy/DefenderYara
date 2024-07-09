
rule Ransom_Win32_FileCoder_GI_MTB{
	meta:
		description = "Ransom:Win32/FileCoder.GI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 94 01 2d ad 00 00 2b 95 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 89 15 90 1b 01 a1 90 1b 01 2d 2d ad 00 00 a3 90 1b 01 8b 0d ?? ?? ?? ?? 03 8d 90 1b 00 03 } //2
		$a_03_1 = {54 68 70 69 20 70 3b 75 67 72 28 73 20 63 38 74 6e 6f 45 3e 62 65 69 68 75 6e 69 6f 6e 20 [0-03] 54 53 20 2c 75 64 65 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}