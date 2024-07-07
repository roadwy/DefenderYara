
rule Ransom_Win32_SodinokibiCrypt_SN_MTB{
	meta:
		description = "Ransom:Win32/SodinokibiCrypt.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_02_0 = {56 ff d7 56 ff 15 90 01 04 bd 90 01 04 ff 15 90 01 04 81 3d 90 01 06 00 00 75 90 01 01 56 ff 15 90 01 04 4d 75 90 00 } //2
		$a_02_1 = {53 56 33 db 33 f6 81 fe 90 01 02 00 00 7d 06 ff 15 90 01 04 81 fe 90 01 04 7e 24 81 bd 90 01 02 ff ff 90 01 04 74 18 81 bd 90 01 02 00 00 90 01 02 00 00 74 0c 81 bd 90 01 02 ff ff 90 01 04 75 0b 46 81 fe 90 01 04 7c 90 00 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2) >=4
 
}