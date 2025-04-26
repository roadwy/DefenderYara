
rule Trojan_WinNT_Otlard_G{
	meta:
		description = "Trojan:WinNT/Otlard.G,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 48 38 51 6a 00 ff 55 fc } //1
		$a_01_1 = {b8 2c f1 df ff 8b 00 66 25 01 f0 48 66 81 38 4d 5a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}