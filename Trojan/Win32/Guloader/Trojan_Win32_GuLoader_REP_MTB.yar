
rule Trojan_Win32_GuLoader_REP_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.REP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {5c 68 65 6e 66 72 74 65 5c 69 73 6f 64 75 6c 63 69 74 65 5c 49 6e 64 65 6b 73 6b 6f 6e 74 72 61 6b 74 65 72 6e 65 73 31 32 38 } //1 \henfrte\isodulcite\Indekskontrakternes128
		$a_81_1 = {5c 73 6c 69 6b 70 6f 72 72 65 6e 73 5c 73 6f 6e 61 6e 74 65 72 6e 65 73 5c 6c 61 65 73 65 68 61 73 74 69 67 68 65 64 65 6e 2e 69 6e 69 } //1 \slikporrens\sonanternes\laesehastigheden.ini
		$a_81_2 = {5c 6b 61 72 69 74 74 61 5c 61 6d 65 72 69 6b 61 5c 75 6e 73 61 6e 63 74 69 6f 6e 65 64 2e 6a 70 67 } //1 \karitta\amerika\unsanctioned.jpg
		$a_81_3 = {25 6f 6e 79 6d 79 25 5c 73 6e 6f 77 77 6f 72 6d 5c 72 75 6e 64 65 73 61 6e 67 65 6e 65 73 } //1 %onymy%\snowworm\rundesangenes
		$a_81_4 = {5c 46 61 63 69 65 73 74 31 35 36 5c 53 75 70 65 72 65 78 63 69 74 65 6d 65 6e 74 2e 65 78 65 } //1 \Faciest156\Superexcitement.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}