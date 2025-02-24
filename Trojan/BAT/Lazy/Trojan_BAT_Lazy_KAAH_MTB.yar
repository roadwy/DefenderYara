
rule Trojan_BAT_Lazy_KAAH_MTB{
	meta:
		description = "Trojan:BAT/Lazy.KAAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_01_0 = {47 7e 25 57 87 a8 26 9a 75 02 db 6a 6b 9a 29 4b 5e 8a 47 98 fe a3 b7 46 c6 86 ec } //4
		$a_01_1 = {a1 c3 fb a2 a4 ec d7 57 3d 4a 88 41 9a f0 4e 8c e6 20 30 ce 6c c7 65 26 65 56 } //3
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*3) >=7
 
}