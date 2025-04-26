
rule Trojan_Win32_Wabot_GME_MTB{
	meta:
		description = "Trojan:Win32/Wabot.GME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6d 61 72 69 6a 75 61 6e 61 2e 74 78 74 } //1 marijuana.txt
		$a_01_1 = {71 55 46 44 5a 50 53 68 70 70 74 63 46 51 71 } //1 qUFDZPShpptcFQq
		$a_01_2 = {62 4b 44 50 6d 66 7a 68 65 70 55 51 5a 68 } //1 bKDPmfzhepUQZh
		$a_01_3 = {47 78 65 62 6b 34 4c 68 65 41 41 71 62 50 50 50 46 50 5a 50 5a 51 6b 24 } //1 Gxebk4LheAAqbPPPFPZPZQk$
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Trojan_Win32_Wabot_GME_MTB_2{
	meta:
		description = "Trojan:Win32/Wabot.GME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {74 57 78 35 30 47 47 73 24 43 61 } //1 tWx50GGs$Ca
		$a_01_1 = {4a 63 33 4a 63 33 72 63 63 63 72 66 4a 33 63 63 66 66 66 4a 33 63 33 32 4a 66 72 63 32 66 66 72 33 63 4a 32 } //1 Jc3Jc3rcccrfJ3ccfffJ3c32Jfrc2ffr3cJ2
		$a_01_2 = {64 30 34 6b 4f 35 56 55 4c 23 41 46 46 4c 38 26 59 4f 46 46 63 3d 73 61 6e a3 43 76 2a 71 5a 61 63 } //1
		$a_01_3 = {67 59 44 46 53 51 55 67 44 6a 2d 47 6b 4b 35 6f 56 68 46 4a 21 } //1 gYDFSQUgDj-GkK5oVhFJ!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}