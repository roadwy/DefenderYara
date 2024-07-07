
rule Trojan_Win64_Guidownloader_A{
	meta:
		description = "Trojan:Win64/Guidownloader.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 88 44 24 18 88 54 24 10 48 89 4c 24 08 0f be 44 24 10 f7 d0 0f 90 01 01 4c 24 18 23 c1 0f be 4c 24 10 0f be 54 24 18 f7 d2 23 ca 0b c1 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}