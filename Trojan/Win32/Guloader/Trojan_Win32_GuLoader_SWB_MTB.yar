
rule Trojan_Win32_GuLoader_SWB_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SWB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {5c 42 75 67 74 61 6c 65 72 31 37 37 5c 75 72 62 69 63 6f 6c 6f 75 73 2e 69 6e 69 } //1 \Bugtaler177\urbicolous.ini
		$a_81_1 = {5c 4e 69 65 72 65 6e 73 5c 6d 69 6c 69 6f 6e 64 65 6c 65 6e 65 } //1 \Nierens\miliondelene
		$a_81_2 = {5c 6c 79 73 65 73 74 61 67 65 72 6e 65 73 2e 62 69 6e } //1 \lysestagernes.bin
		$a_81_3 = {5c 73 74 65 61 6d 72 6f 6c 6c 65 72 69 6e 67 2e 68 74 6d } //1 \steamrollering.htm
		$a_81_4 = {5c 75 74 69 6c 69 74 61 72 69 73 6d 65 6e 73 5c 64 69 73 6b 6f 73 6b 61 73 74 65 6e 65 73 2e 6a 70 67 } //1 \utilitarismens\diskoskastenes.jpg
		$a_81_5 = {5c 6d 69 73 76 6b 73 74 65 72 6e 65 73 5c 73 65 72 65 73 2e 65 78 65 } //1 \misvksternes\seres.exe
		$a_81_6 = {4b 6c 69 70 70 65 66 61 73 74 32 31 31 2e 67 65 6f } //1 Klippefast211.geo
		$a_81_7 = {52 6f 6c 6c 65 68 65 66 74 65 73 32 32 37 2e 6d 75 63 } //1 Rolleheftes227.muc
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}