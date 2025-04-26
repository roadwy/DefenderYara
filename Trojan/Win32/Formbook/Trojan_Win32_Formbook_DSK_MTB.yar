
rule Trojan_Win32_Formbook_DSK_MTB{
	meta:
		description = "Trojan:Win32/Formbook.DSK!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 0c 03 55 ec 8b 45 08 03 45 f8 8a 0a 32 08 8b 55 0c 03 55 ec 88 0a e9 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}