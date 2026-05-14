
rule Trojan_Win32_GuLoader_SWG_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SWG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {5c 45 6e 64 61 6d 65 62 61 65 5c 54 72 6f 6e 65 72 6e 65 73 2e 69 6e 69 } //1 \Endamebae\Tronernes.ini
		$a_81_1 = {5c 55 6e 76 65 6e 65 72 61 74 69 76 65 39 39 2e 68 74 6d } //1 \Unvenerative99.htm
		$a_81_2 = {5c 75 6e 63 68 61 72 74 65 72 65 64 2e 62 69 6e } //1 \unchartered.bin
		$a_81_3 = {5c 63 6f 6c 75 6d 62 61 72 69 65 73 5c 6c 79 73 65 73 74 61 67 65 72 6e 65 2e 64 6c 6c } //1 \columbaries\lysestagerne.dll
		$a_81_4 = {5c 61 6e 6e 61 6d 6d 65 6c 73 65 72 73 2e 68 74 6d } //1 \annammelsers.htm
		$a_81_5 = {5c 64 65 76 6f 74 69 6f 6e 61 6c 5c 70 72 69 73 62 65 6c 6e 6e 65 73 2e 67 69 66 } //1 \devotional\prisbelnnes.gif
		$a_81_6 = {5c 4b 76 61 6c 69 66 69 6b 61 74 69 6f 6e 65 72 6e 65 73 5c 65 66 66 65 6b 74 75 65 72 69 6e 67 65 72 6e 65 73 2e 6c 6e 6b } //1 \Kvalifikationernes\effektueringernes.lnk
		$a_81_7 = {49 72 72 65 63 6f 67 6e 69 7a 61 62 6c 79 2e 54 69 6c } //1 Irrecognizably.Til
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}