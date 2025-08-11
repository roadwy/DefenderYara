
rule Trojan_Win32_GuLoader_RAW_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RAW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {5c 75 64 72 79 64 64 65 74 5c 42 65 6e 67 6e 61 76 65 72 6e 65 35 33 5c 75 64 74 75 72 65 6e 65 73 } //1 \udryddet\Bengnaverne53\udturenes
		$a_81_1 = {73 6b 6f 76 6b 61 6e 74 65 72 5c 62 72 79 61 6e 5c 76 61 72 69 6f 63 75 6f 70 6c 65 72 } //1 skovkanter\bryan\variocuopler
		$a_81_2 = {25 42 65 61 64 69 6e 67 73 25 5c 41 62 64 6f 6d 65 6e 5c 53 6d 69 72 63 68 69 6e 67 } //1 %Beadings%\Abdomen\Smirching
		$a_81_3 = {5c 69 6e 74 65 72 72 75 70 74 65 72 5c 66 6f 74 6f 67 72 61 6d 6d 65 74 72 69 2e 6a 70 67 } //1 \interrupter\fotogrammetri.jpg
		$a_81_4 = {5c 67 6f 72 76 61 72 65 68 61 6e 64 65 6c 65 6e 5c 6b 65 6e 64 65 6d 72 6b 65 72 73 2e 68 74 6d } //1 \gorvarehandelen\kendemrkers.htm
		$a_81_5 = {6c 69 67 68 65 64 73 70 75 6e 6b 74 65 72 6e 65 2e 65 78 65 } //1 lighedspunkterne.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}