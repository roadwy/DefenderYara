
rule Trojan_Win32_Emotet_PEN_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PEN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {03 d3 81 e2 90 01 04 79 90 01 01 4a 81 ca 00 ff ff ff 42 8a 54 14 90 01 01 8a 1c 0f 32 d3 88 11 90 09 04 00 8a 54 34 90 00 } //1
		$a_81_1 = {54 6b 6c 51 36 5a 72 25 37 50 62 24 37 72 2a 30 72 48 70 55 68 41 65 78 6a 49 44 34 6a 34 51 43 32 6b 6a 49 46 7b 47 64 52 32 48 42 32 6c 38 4a 67 69 4d 4e 25 62 6d 35 34 6a 69 53 64 2a 55 24 4d 4f 77 4e 40 5a 72 6e 31 75 39 40 47 24 56 5a 4c 74 6b 65 68 75 75 } //1 TklQ6Zr%7Pb$7r*0rHpUhAexjID4j4QC2kjIF{GdR2HB2l8JgiMN%bm54jiSd*U$MOwN@Zrn1u9@G$VZLtkehuu
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}