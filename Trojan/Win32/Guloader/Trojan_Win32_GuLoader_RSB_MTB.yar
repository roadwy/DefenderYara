
rule Trojan_Win32_GuLoader_RSB_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RSB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {5c 61 73 68 69 70 62 6f 61 72 64 5c 6b 65 6c 6c 65 6e 5c 6b 6e 6f 73 } //1 \ashipboard\kellen\knos
		$a_81_1 = {5c 4f 72 64 62 6f 67 73 5c 61 64 6a 75 64 61 6e 74 73 6e 6f 72 65 6e 65 73 2e 45 78 74 32 34 31 } //1 \Ordbogs\adjudantsnorenes.Ext241
		$a_81_2 = {5c 4d 65 6c 6c 65 6d 6d 6e 64 65 6e 65 73 32 32 34 2e 69 6e 69 } //1 \Mellemmndenes224.ini
		$a_81_3 = {25 76 65 6a 6c 65 64 6e 69 6e 67 73 25 5c 61 72 74 69 6c 6c 65 72 79 6d 65 6e 5c 77 6f 6f 64 68 75 6e 67 2e 70 72 61 } //1 %vejlednings%\artillerymen\woodhung.pra
		$a_81_4 = {5c 67 65 6e 6e 65 6d 74 72 61 77 6c 65 73 5c 67 61 73 74 72 6f 73 6b 6f 70 69 65 72 6e 65 2e 64 6c 6c } //1 \gennemtrawles\gastroskopierne.dll
		$a_81_5 = {5c 68 79 64 72 61 6e 74 68 73 5c 44 79 6e 61 6d 69 73 74 69 63 2e 70 72 65 } //1 \hydranths\Dynamistic.pre
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}