
rule Ransom_Win32_Filecoder_PAGV_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.PAGV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {c7 00 5c 72 65 63 c7 40 04 6f 76 65 72 c7 40 06 65 72 79 2e c7 40 0a 65 78 65 00 c7 44 24 08 00 00 00 00 8d 85 f0 fd ff ff 89 44 24 04 8d 85 f4 fe ff ff 89 04 24 a1 } //2
		$a_01_1 = {8b 45 f4 ba 00 00 00 00 f7 75 f0 89 d0 8b 44 85 b4 31 c1 8b 45 14 8b 55 f4 81 c2 00 04 00 00 89 0c 90 83 45 f4 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}