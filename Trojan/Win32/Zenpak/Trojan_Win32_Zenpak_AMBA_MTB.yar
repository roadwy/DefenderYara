
rule Trojan_Win32_Zenpak_AMBA_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.AMBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 e8 8b 4d ec 8a 14 01 8b 45 e8 8b 4d f0 88 14 01 8b 45 e8 05 01 00 00 00 89 45 e8 eb } //1
		$a_80_1 = {4c 6e 6c 74 65 65 68 4f 73 74 65 72 62 70 } //LnlteehOsterbp  1
	condition:
		((#a_01_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}