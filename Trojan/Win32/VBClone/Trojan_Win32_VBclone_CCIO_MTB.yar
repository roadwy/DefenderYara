
rule Trojan_Win32_VBclone_CCIO_MTB{
	meta:
		description = "Trojan:Win32/VBclone.CCIO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {c7 45 fc 03 00 00 00 c7 85 04 ff ff ff 94 30 40 00 c7 85 fc fe ff ff 08 00 00 00 8d 95 fc fe ff ff 8d 8d 2c ff ff ff ff 15 } //5
		$a_01_1 = {50 72 6f 79 65 63 74 6f 31 } //1 Proyecto1
		$a_01_2 = {49 6e 66 65 63 74 4d 6f 64 75 6c 65 } //1 InfectModule
		$a_01_3 = {51 00 61 00 70 00 6b 00 72 00 76 00 6b 00 6c 00 65 00 2c 00 44 00 6b 00 6e 00 67 00 51 00 7b 00 71 00 76 00 67 00 6f 00 4d 00 60 00 68 00 67 00 61 00 76 00 } //1 Qapkrvkle,DkngQ{qvgoM`hgav
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}