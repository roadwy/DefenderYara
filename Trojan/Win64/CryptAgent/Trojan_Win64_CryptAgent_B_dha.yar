
rule Trojan_Win64_CryptAgent_B_dha{
	meta:
		description = "Trojan:Win64/CryptAgent.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {80 38 47 75 36 80 78 01 65 75 30 80 78 02 74 75 2a 80 78 03 50 75 24 80 78 04 72 75 1e 80 78 05 6f 75 18 80 78 06 63 75 12 80 78 07 41 75 0c 80 78 08 64 75 06 80 78 09 64 74 1c } //1
		$a_01_1 = {80 74 05 80 cc 48 ff c0 48 83 f8 42 7c f2 } //1
		$a_01_2 = {80 74 04 50 aa 48 ff c0 48 83 f8 27 7c f2 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}