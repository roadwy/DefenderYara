
rule Trojan_BAT_Genmalmil{
	meta:
		description = "Trojan:BAT/Genmalmil,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 64 6f 62 65 20 44 6f 77 6e 6c 6f 61 64 20 4d 61 6e 61 67 65 72 00 } //1
		$a_01_1 = {50 6f 77 65 72 65 64 20 62 79 20 53 6d 61 72 74 41 73 73 65 6d 62 6c 79 } //1 Powered by SmartAssembly
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}