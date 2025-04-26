
rule Trojan_Win32_GuLoader_RSL_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RSL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {5c 4c 69 76 69 64 69 74 69 65 73 5c 69 6e 64 6c 61 65 67 67 65 72 5c 6e 6f 6e 63 61 70 69 6c 6c 61 72 69 65 73 } //1 \Lividities\indlaegger\noncapillaries
		$a_81_1 = {38 38 5c 44 69 73 72 65 73 70 65 63 74 69 76 65 5c 6d 6f 75 73 65 77 65 62 2e 73 75 70 } //1 88\Disrespective\mouseweb.sup
		$a_81_2 = {37 5c 63 61 72 79 6f 70 68 79 6c 6c 65 6e 65 2e 62 61 63 } //1 7\caryophyllene.bac
		$a_81_3 = {25 46 61 72 63 69 63 61 6c 69 74 79 31 31 35 25 5c 76 65 6e 75 73 } //1 %Farcicality115%\venus
		$a_81_4 = {5c 62 65 61 72 6e 61 69 73 65 6e 73 5c 6c 65 6a 65 6e 2e 6d 61 63 } //1 \bearnaisens\lejen.mac
		$a_81_5 = {6b 6f 6c 6f 6e 69 61 6c 74 20 62 69 6c 6c 65 64 74 70 70 65 74 2e 65 78 65 } //1 kolonialt billedtppet.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}