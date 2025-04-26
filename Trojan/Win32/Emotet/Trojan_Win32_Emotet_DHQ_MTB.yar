
rule Trojan_Win32_Emotet_DHQ_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DHQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_00_0 = {8b 01 ba ff fe fe 7e 03 d0 83 f0 ff 33 c2 83 c1 04 } //1
		$a_00_1 = {33 d2 8a 51 01 8b 4d f8 8b 04 81 33 c2 8b 4d 14 88 41 01 8b 55 f4 83 c2 01 81 e2 ff 00 00 00 89 55 f4 } //1
		$a_01_2 = {45 00 78 00 6c 00 4f 00 36 00 38 00 4f 00 74 00 66 00 66 00 61 00 43 00 58 00 30 00 7a 00 39 00 72 00 58 00 } //5 ExlO68OtffaCX0z9rX
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*5) >=7
 
}