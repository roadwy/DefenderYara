
rule Worm_Win32_Vobfus_G_MTB{
	meta:
		description = "Worm:Win32/Vobfus.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 00 32 08 00 28 ff 24 ff 20 ff 1c ff 1a e8 fe 00 } //10
		$a_01_1 = {56 69 72 75 73 20 61 73 6c 69 20 62 75 61 74 61 6e 20 41 6d 62 6f 6e 20 4d 61 6e 69 73 65 2d 4d 61 6c 75 6b 75 } //1 Virus asli buatan Ambon Manise-Maluku
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}