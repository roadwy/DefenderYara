
rule Trojan_Win32_Delf_ES{
	meta:
		description = "Trojan:Win32/Delf.ES,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {26 63 6f 6e 74 65 75 64 6f 3d } //1 &conteudo=
		$a_01_1 = {50 4f 53 54 20 2f 65 6d 61 69 6c 2e 70 68 70 20 48 54 54 50 2f 31 2e 30 0d 0a } //1
		$a_03_2 = {bf 01 00 00 00 8b 45 fc 8a 5c 38 ff 80 e3 0f b8 90 01 04 8a 44 30 ff 24 0f 32 d8 80 f3 0a 8d 45 fc e8 90 01 04 8b 55 fc 8a 54 3a ff 80 e2 f0 02 d3 88 54 38 ff 46 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}