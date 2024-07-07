
rule Trojan_Win32_Emotet_AF_MTB{
	meta:
		description = "Trojan:Win32/Emotet.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff 4c 24 08 75 09 8b 44 24 04 a3 90 01 04 33 c0 40 c2 0c 00 55 8b ec 83 ec 1c ff 75 90 00 } //1
		$a_03_1 = {81 75 f8 ec 93 47 0f 81 45 f8 db 9c 00 00 81 75 f8 be ba 44 0f 83 3c b5 90 01 04 00 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}