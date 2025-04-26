
rule Trojan_Win64_Lazy_ALY_MTB{
	meta:
		description = "Trojan:Win64/Lazy.ALY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 40 33 db 89 05 0f a3 75 00 8b 44 24 24 89 05 09 a3 75 00 8b 44 24 48 89 05 03 a3 75 00 89 5c 24 60 88 1d fe a2 75 00 e8 } //2
		$a_01_1 = {48 89 74 24 40 b8 20 00 00 00 8b 74 24 30 c1 ee 05 8b ce 48 f7 e1 48 c7 c1 ff ff ff ff 48 89 7c 24 20 48 8d 15 2b 65 6b 00 48 0f 42 c1 48 8b c8 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}