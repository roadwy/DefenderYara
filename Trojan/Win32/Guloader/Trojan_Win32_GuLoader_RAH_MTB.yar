
rule Trojan_Win32_GuLoader_RAH_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {5c 4b 6f 62 62 65 72 73 74 69 6b 6b 65 74 31 36 39 5c 68 65 6c 69 63 6f 67 72 61 70 68 } //1 \Kobberstikket169\helicograph
		$a_81_1 = {25 6d 75 6c 69 73 68 6e 65 73 73 25 5c 4e 6f 6e 6c 65 61 6b 69 6e 67 2e 62 69 6e } //1 %mulishness%\Nonleaking.bin
		$a_81_2 = {67 61 6c 65 69 64 61 65 20 6f 70 61 72 62 65 6a 64 65 6c 73 65 72 6e 65 73 20 6f 75 74 62 65 61 72 } //1 galeidae oparbejdelsernes outbear
		$a_81_3 = {65 66 74 65 72 73 69 64 6e 69 6e 67 65 72 20 62 69 73 74 61 6e 64 73 6b 6c 69 65 6e 74 65 6e 73 20 75 6e 73 75 70 65 72 66 69 63 69 61 6c } //1 eftersidninger bistandsklientens unsuperficial
		$a_81_4 = {73 6b 69 6c 6c 65 76 67 67 65 } //1 skillevgge
		$a_81_5 = {64 65 64 69 63 65 72 65 6e 64 65 73 20 73 69 6e 74 6f 69 73 6d 2e 65 78 65 } //1 dedicerendes sintoism.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}