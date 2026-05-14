
rule Trojan_Win32_Amatera_AME_MTB{
	meta:
		description = "Trojan:Win32/Amatera.AME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 1c 24 89 c6 8d 44 24 1c c7 44 24 08 40 00 00 00 89 74 24 04 89 44 24 0c ff d7 83 ec 10 89 74 24 08 89 6c 24 04 89 1c 24 e8 ?? ?? ?? ?? 8d 44 24 18 89 74 24 04 89 44 24 0c 8b 44 24 1c 89 1c 24 89 44 24 08 ff d7 } //3
		$a_01_1 = {69 6f 72 6c 7a 75 70 6f 61 68 75 69 } //2 iorlzupoahui
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}