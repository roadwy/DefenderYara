
rule Trojan_Win32_MysticStealer_ASES_MTB{
	meta:
		description = "Trojan:Win32/MysticStealer.ASES!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {66 6f 69 74 67 73 64 6d 79 69 66 6b 6d 6d 66 62 63 79 79 71 6d 63 68 6a 76 78 73 72 6a 7a 6a 69 6b 62 70 6a 76 65 6a 70 6e 62 69 7a 6f 67 6f 68 77 6d 73 62 6c 6c 6d 6d 66 70 64 68 61 63 72 79 68 63 73 78 69 7a 61 } //1 foitgsdmyifkmmfbcyyqmchjvxsrjzjikbpjvejpnbizogohwmsbllmmfpdhacryhcsxiza
		$a_01_1 = {75 65 6a 78 72 67 74 75 6a 70 68 65 6f 6c 78 6e 6b 79 70 64 61 75 7a 64 6f 66 6f 66 68 64 78 72 62 73 6d 7a 63 } //1 uejxrgtujpheolxnkypdauzdofofhdxrbsmzc
		$a_01_2 = {6b 71 61 6d 6e 65 7a 74 7a 66 7a 6e 74 77 6c 78 71 6c 79 66 7a 62 66 68 77 } //1 kqamneztzfzntwlxqlyfzbfhw
		$a_01_3 = {71 63 6e 68 67 71 75 73 66 78 64 65 71 62 79 6d 68 66 75 65 62 6f 76 79 6b 79 63 72 79 63 6e 72 71 6a 69 75 6b 77 66 77 78 68 75 70 65 79 6f 62 75 6e 72 64 66 62 65 70 72 64 77 68 6b } //1 qcnhgqusfxdeqbymhfuebovykycrycnrqjiukwfwxhupeyobunrdfbeprdwhk
		$a_01_4 = {6f 6d 62 6d 66 6a 68 69 6d 61 72 76 63 70 6a 6d 76 6e 7a 71 6c 67 76 72 71 68 70 63 66 6e 71 62 6d 75 6c 6c 78 79 6b 62 6e 66 71 78 79 61 76 6f 69 } //1 ombmfjhimarvcpjmvnzqlgvrqhpcfnqbmullxykbnfqxyavoi
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}