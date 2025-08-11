
rule Trojan_Win32_Dapato_GVA_MTB{
	meta:
		description = "Trojan:Win32/Dapato.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 fe 81 ef 89 15 00 00 03 c7 31 03 83 45 ec 04 6a 00 } //2
		$a_01_1 = {8b 13 03 55 ec 2b d0 89 13 8b 45 d4 03 45 a4 03 45 ec 03 f0 bf 89 15 00 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}