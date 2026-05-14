
rule Trojan_Win32_GuLoader_REE_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.REE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {68 61 73 74 65 73 61 67 65 72 73 5c 6c 65 64 67 65 72 73 5c 62 72 79 73 74 6e 69 6e 67 73 } //1 hastesagers\ledgers\brystnings
		$a_81_1 = {5c 45 6e 64 61 6d 65 62 61 65 5c 54 72 6f 6e 65 72 6e 65 73 2e 69 6e 69 } //1 \Endamebae\Tronernes.ini
		$a_81_2 = {5c 64 65 76 6f 74 69 6f 6e 61 6c 5c 70 72 69 73 62 65 6c 6e 6e 65 73 2e 67 69 66 } //1 \devotional\prisbelnnes.gif
		$a_81_3 = {4b 76 61 6c 69 66 69 6b 61 74 69 6f 6e 65 72 6e 65 73 5c 65 66 66 65 6b 74 75 65 72 69 6e 67 65 72 6e 65 73 2e 6c 6e 6b } //1 Kvalifikationernes\effektueringernes.lnk
		$a_81_4 = {25 72 65 6e 67 72 69 6e 67 73 61 73 73 69 73 74 65 6e 74 65 6e 25 5c 50 72 6f 6d 69 6e 69 73 74 72 79 31 39 38 5c 45 78 74 72 69 63 61 62 6c 65 } //1 %rengringsassistenten%\Proministry198\Extricable
		$a_81_5 = {5c 75 6e 69 6e 6e 6f 63 75 6f 75 73 6c 79 5c 77 68 6f 72 65 6d 61 73 74 65 72 6c 79 2e 74 78 74 } //1 \uninnocuously\whoremasterly.txt
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}