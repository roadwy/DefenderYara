
rule Trojan_Win32_Guloader_CQ_MTB{
	meta:
		description = "Trojan:Win32/Guloader.CQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {56 61 70 6f 75 72 69 73 61 62 6c 65 31 31 31 5c 6f 72 74 68 6f 73 5c 69 6e 74 65 72 72 65 67 6e 61 } //1 Vapourisable111\orthos\interregna
		$a_81_1 = {70 69 65 7a 6f 63 72 79 73 74 61 6c 6c 69 7a 61 74 69 6f 6e 2e 64 6c 6c } //1 piezocrystallization.dll
		$a_81_2 = {74 65 74 72 61 7a 6f 6c 79 6c 5c 62 61 6c 6c 6f 6e 73 6b 69 70 70 65 72 6e 65 73 2e 6c 6e 6b } //1 tetrazolyl\ballonskippernes.lnk
		$a_81_3 = {73 6e 69 70 73 6e 61 70 73 6e 6f 72 75 6d 5c 67 61 6e 63 68 2e 6f 76 65 } //1 snipsnapsnorum\ganch.ove
		$a_81_4 = {46 69 72 6d 61 6d 65 6e 74 65 72 73 5c 45 6e 6b 65 6c 74 68 65 64 65 72 6e 65 73 2e 69 6e 69 } //1 Firmamenters\Enkelthedernes.ini
		$a_81_5 = {72 75 6e 64 62 6f 72 64 73 73 61 6d 74 61 6c 65 72 6e 65 73 5c 64 77 74 2e 75 64 74 } //1 rundbordssamtalernes\dwt.udt
		$a_81_6 = {4e 6f 72 6d 61 6e 6e 65 72 65 73 31 34 34 2e 74 61 6a } //1 Normanneres144.taj
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}