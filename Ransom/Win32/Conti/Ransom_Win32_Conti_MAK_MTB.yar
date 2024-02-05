
rule Ransom_Win32_Conti_MAK_MTB{
	meta:
		description = "Ransom:Win32/Conti.MAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8a 06 8d 76 01 0f b6 c0 83 e8 90 02 01 6b c0 90 02 01 99 f7 fb 8d 42 90 02 01 99 f7 fb 88 56 ff 83 ef 01 75 90 00 } //01 00 
		$a_80_1 = {65 78 70 61 6e 64 20 33 32 2d 62 79 74 65 20 6b } //expand 32-byte k  01 00 
		$a_80_2 = {65 78 70 61 6e 64 20 31 36 2d 62 79 74 65 20 6b } //expand 16-byte k  00 00 
		$a_00_3 = {5d 04 00 00 db a1 04 80 5c 3d } //00 00 
	condition:
		any of ($a_*)
 
}