
rule Trojan_Win32_RedLine_SPDF_MTB{
	meta:
		description = "Trojan:Win32/RedLine.SPDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6b 64 78 68 7a 72 63 62 69 6b 6d 64 65 69 66 73 62 62 79 77 75 6e 6c 63 71 6e 72 75 77 75 72 66 64 69 73 70 62 7a 6d 74 66 61 73 63 69 61 67 } //1 kdxhzrcbikmdeifsbbywunlcqnruwurfdispbzmtfasciag
		$a_01_1 = {70 64 75 71 73 62 67 67 69 72 76 67 74 68 65 71 6a 70 6f 66 76 67 77 68 72 74 77 73 6a 74 61 6d 6f 7a 78 6e 68 75 65 7a 64 73 76 72 6a } //1 pduqsbggirvgtheqjpofvgwhrtwsjtamozxnhuezdsvrj
		$a_01_2 = {6b 69 73 6b 63 75 72 6b 6b 67 78 6d 66 6d 61 6e 6c 72 6b 71 66 71 71 72 6e 65 73 72 61 6f 67 6e 64 74 78 6f 77 6a 71 6f 70 61 65 61 72 62 76 66 66 70 6d 79 62 74 76 78 71 6b 6f 66 76 6b 79 61 78 70 78 65 6e 77 77 70 70 6e 72 75 69 64 62 70 6d 74 70 65 71 73 7a 66 73 6e 79 67 66 64 } //1 kiskcurkkgxmfmanlrkqfqqrnesraogndtxowjqopaearbvffpmybtvxqkofvkyaxpxenwwppnruidbpmtpeqszfsnygfd
		$a_01_3 = {77 77 77 6c 72 6e 6d 65 6b 75 71 72 74 73 64 77 77 6c 66 78 73 69 72 67 79 70 74 67 61 6a 7a 64 75 74 61 70 72 68 63 7a 79 6c 7a 6d 75 6a 79 70 76 73 75 6a 6e 64 67 69 73 62 69 64 69 6d 77 71 62 65 6f 6f 7a 78 61 61 74 64 62 6e 73 79 64 71 6b 61 6b 6b 74 6e 73 6a 62 74 6c 69 6b } //1 wwwlrnmekuqrtsdwwlfxsirgyptgajzdutaprhczylzmujypvsujndgisbidimwqbeoozxaatdbnsydqkakktnsjbtlik
		$a_01_4 = {72 6a 62 61 72 74 70 79 77 67 66 76 64 6d 62 77 6d 6f 77 63 6b 75 61 6c 73 73 61 62 7a 71 6b 73 6e 63 7a 6d 79 71 76 76 71 62 6a 78 69 65 74 75 68 6f 77 6b 74 68 65 7a 66 6c 78 65 62 6e 71 74 71 69 69 6d 64 6e 6f 73 70 67 74 71 65 76 6e 68 67 77 76 74 6e 6f 75 77 61 6f 7a 6d 78 } //1 rjbartpywgfvdmbwmowckualssabzqksnczmyqvvqbjxietuhowkthezflxebnqtqiimdnospgtqevnhgwvtnouwaozmx
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}