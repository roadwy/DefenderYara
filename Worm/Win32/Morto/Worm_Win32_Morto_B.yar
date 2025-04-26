
rule Worm_Win32_Morto_B{
	meta:
		description = "Worm:Win32/Morto.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {ff 75 0c ff 76 30 ff 75 08 ff 15 ?? ?? ?? ?? 83 c4 0c 85 c0 74 04 8b 36 eb } //1
		$a_02_1 = {83 c4 0c 89 85 ?? ?? ?? ?? 68 00 02 00 00 8d 85 f0 fd ff ff 50 ff 75 08 ff 95 } //1
		$a_00_2 = {6a 08 50 c7 45 b0 4b 00 65 00 c7 45 b4 72 00 6e 00 c7 45 b8 65 00 6c 00 c7 45 bc 33 00 32 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=2
 
}