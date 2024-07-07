
rule Trojan_Win32_Pterodo_G{
	meta:
		description = "Trojan:Win32/Pterodo.G,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 4b 42 4a 80 30 60 60 61 80 30 72 53 31 db 5b 40 48 80 28 88 53 31 db 5b 80 30 f6 53 31 db 5b 80 00 95 90 80 28 7b 42 4a 80 00 40 43 4b 80 28 11 60 61 80 00 15 } //1
		$a_01_1 = {2e 65 78 65 00 5c 00 6f 70 65 6e 00 5c 4d 69 72 61 2e 68 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}