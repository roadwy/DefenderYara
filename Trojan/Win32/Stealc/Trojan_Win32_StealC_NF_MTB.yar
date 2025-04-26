
rule Trojan_Win32_StealC_NF_MTB{
	meta:
		description = "Trojan:Win32/StealC.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_81_0 = {67 75 7a 75 67 69 63 69 6a 69 78 69 66 65 68 61 70 61 7a 69 } //2 guzugicijixifehapazi
		$a_81_1 = {62 69 72 65 74 6f 64 75 74 61 } //1 biretoduta
		$a_81_2 = {6b 69 77 69 6a 65 6c 69 74 6f 78 69 6a } //1 kiwijelitoxij
		$a_81_3 = {79 75 6d 65 68 65 68 65 67 69 6b 65 64 6f 6a 6f 74 6f 67 6f 72 65 6b 6f 73 75 73 75 } //1 yumehehegikedojotogorekosusu
		$a_81_4 = {6d 69 6b 75 6c 61 6d 75 6a 75 73 69 6e 75 74 65 77 61 76 6f 79 69 } //1 mikulamujusinutewavoyi
		$a_81_5 = {6d 73 69 6d 67 33 32 2e 64 6c 6c } //1 msimg32.dll
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=7
 
}