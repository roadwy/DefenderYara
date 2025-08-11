
rule Trojan_Win64_Barys_NB_MTB{
	meta:
		description = "Trojan:Win64/Barys.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 07 09 c0 74 4a 8b 5f 04 48 8d 8c 30 ?? ?? ?? ?? 48 01 f3 48 83 c7 08 ff 15 60 0b 00 00 48 95 } //3
		$a_01_1 = {48 89 f9 48 89 fa ff c8 f2 ae 48 89 e9 ff 15 52 0b 00 00 48 09 c0 74 09 } //1
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}
rule Trojan_Win64_Barys_NB_MTB_2{
	meta:
		description = "Trojan:Win64/Barys.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {54 61 79 66 61 20 50 72 6f 78 79 } //1 Tayfa Proxy
		$a_01_1 = {50 41 52 4b 4f 55 52 58 } //1 PARKOURX
		$a_01_2 = {42 61 67 6c 61 6e 74 69 20 68 61 74 61 73 69 21 } //1 Baglanti hatasi!
		$a_01_3 = {44 6f 6e 65 20 48 54 54 50 53 21 } //1 Done HTTPS!
		$a_01_4 = {54 61 79 66 61 20 50 72 6f 78 79 20 62 79 20 4b 61 79 69 70 20 61 6e 64 20 54 68 72 6f 78 79 } //1 Tayfa Proxy by Kayip and Throxy
		$a_01_5 = {59 6f 75 20 63 61 6e 20 6e 6f 77 20 63 6f 6e 6e 65 63 74 20 74 6f 20 47 72 6f 77 74 6f 70 69 61 } //1 You can now connect to Growtopia
		$a_01_6 = {47 65 6d 73 20 74 6f 20 41 76 6f 69 64 20 6a 65 62 73 21 2c 20 4e 6f 77 20 47 65 6d 73 20 69 73 } //1 Gems to Avoid jebs!, Now Gems is
		$a_01_7 = {42 61 73 69 6c 61 6e 20 74 75 73 } //1 Basilan tus
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}