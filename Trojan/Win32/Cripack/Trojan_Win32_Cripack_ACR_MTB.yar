
rule Trojan_Win32_Cripack_ACR_MTB{
	meta:
		description = "Trojan:Win32/Cripack.ACR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {88 4d b4 0f be 55 f8 0f be 45 a8 2b d0 8b 4d fc 03 ca 89 4d fc 0f be 55 bc 0f be 45 a8 2b d0 81 ea e5 03 00 00 8b 4d fc 2b ca 89 4d fc 8b 55 b0 0f be 02 0c 20 8b 4d f0 33 c8 } //2
		$a_01_1 = {89 55 ec 0f be 45 b4 0f be 4d f8 03 c1 8a 55 c0 2a d0 88 55 c0 8b 45 f4 69 c0 4f ff ff ff 05 e1 01 00 00 8a 4d c0 2a c8 88 4d c0 8b 55 b0 83 c2 01 89 55 b0 8b 45 b0 0f be 08 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}