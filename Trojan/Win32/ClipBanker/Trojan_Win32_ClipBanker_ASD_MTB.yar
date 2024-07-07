
rule Trojan_Win32_ClipBanker_ASD_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.ASD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {33 45 6a 68 6a 44 66 73 75 21 55 73 76 74 75 66 65 21 48 35 21 53 54 42 35 31 3a 37 21 54 49 42 33 36 37 21 55 6a 6e 66 54 75 62 6e 71 6a 6f 68 21 44 42 31 } //1 3EjhjDfsu!Usvtufe!H5!STB51:7!TIB367!UjnfTubnqjoh!DB1
		$a_01_1 = {55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 77 6e 6c 6f 61 64 73 5c 5a 54 58 43 6c 69 65 6e 74 6e 2e 65 78 65 } //1 Users\Public\Downloads\ZTXClientn.exe
		$a_01_2 = {69 75 75 71 3b 30 30 70 64 74 71 2f 65 6a 68 6a 64 66 73 75 2f 64 70 6e 31 44 } //1 iuuq;00pdtq/ejhjdfsu/dpn1D
		$a_01_3 = {78 78 78 2f 65 6a 68 6a 64 66 73 75 2f 64 70 6e 32 } //1 xxx/ejhjdfsu/dpn2
		$a_01_4 = {45 6a 68 6a 44 66 73 75 21 55 73 76 74 75 66 65 21 53 70 70 75 21 48 35 31 } //1 EjhjDfsu!Usvtufe!Sppu!H51
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}