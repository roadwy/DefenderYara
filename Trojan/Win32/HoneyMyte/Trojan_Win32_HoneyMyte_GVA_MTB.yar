
rule Trojan_Win32_HoneyMyte_GVA_MTB{
	meta:
		description = "Trojan:Win32/HoneyMyte.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 69 88 ec 01 00 00 fd 43 03 00 81 c1 c3 9e 26 00 8b 55 08 89 8a ec 01 00 00 8b 45 08 8b 80 ec 01 00 00 5f 5e 5b 81 c4 c0 00 00 00 3b ec } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}