
rule Trojan_Linux_Ladvix_B_MTB{
	meta:
		description = "Trojan:Linux/Ladvix.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3a 54 05 00 75 0f 41 0f b6 34 06 48 63 cb 83 c3 01 40 88 34 0c 48 83 c0 01 48 83 f8 58 75 e1 49 83 c7 01 4c 89 ef e8 c5 f6 ff ff 4c 39 f8 77 c8 4c 89 e7 48 63 db c6 04 1c 00 e8 51 f8 ff ff 48 8b bc 24 08 02 00 00 64 48 33 3c 25 28 00 00 00 75 12 48 81 c4 18 02 } //1
		$a_01_1 = {59 6d 39 75 5a 33 4a 70 63 48 6f 30 61 6d 56 36 64 58 6f 4b } //1 Ym9uZ3JpcHo0amV6dXoK
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}