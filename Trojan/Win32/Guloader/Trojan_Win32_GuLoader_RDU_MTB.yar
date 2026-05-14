
rule Trojan_Win32_GuLoader_RDU_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RDU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {50 72 6f 6d 61 78 69 6d 75 6d 31 35 30 5c 6d 61 6c 69 68 69 6e 69 5c 42 6f 6c 69 67 73 65 6c 73 6b 61 62 65 74 } //1 Promaximum150\malihini\Boligselskabet
		$a_81_1 = {6d 6f 64 65 6c 6c 6e 66 72 5c 52 65 6f 72 67 61 6e 69 73 65 72 65 6e 64 65 31 36 36 } //1 modellnfr\Reorganiserende166
		$a_81_2 = {25 4c 65 6e 73 6d 61 6e 64 65 6e 25 5c 67 65 6f 6d 6f 72 66 6f 6c 6f 67 69 } //1 %Lensmanden%\geomorfologi
		$a_81_3 = {5c 55 6e 64 73 74 6e 69 6e 67 73 61 6b 74 69 6f 6e 5c 73 61 70 72 6f 6d 69 63 2e 6a 70 67 } //1 \Undstningsaktion\sapromic.jpg
		$a_81_4 = {5c 73 6b 79 74 74 65 66 69 73 6b 73 2e 67 69 66 } //1 \skyttefisks.gif
		$a_81_5 = {5c 61 6c 73 74 72 75 70 73 5c 6f 76 65 72 66 6c 73 6f 6d 2e 69 6e 69 } //1 \alstrups\overflsom.ini
		$a_81_6 = {5c 70 68 6f 6e 65 74 69 63 6f 68 69 65 72 6f 67 6c 79 70 68 69 63 2e 65 78 65 } //1 \phoneticohieroglyphic.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}