
rule TrojanDownloader_Win64_Lazy_E_MTB{
	meta:
		description = "TrojanDownloader:Win64/Lazy.E!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {d9 eb d9 fc 0f 31 48 c1 e2 20 48 0b c2 48 2b c1 49 3b c1 } //1
		$a_01_1 = {49 ff ca 4d 33 db 48 ff c8 48 83 c4 08 5d c3 } //1
		$a_01_2 = {3b c8 48 f7 d3 0f 42 c8 49 23 dc 49 8d 44 3d 00 8b f1 48 2b de 48 3b d8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}