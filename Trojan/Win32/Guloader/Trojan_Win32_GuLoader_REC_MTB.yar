
rule Trojan_Win32_GuLoader_REC_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.REC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {25 53 77 69 6e 64 6c 69 6e 67 32 36 25 5c 62 69 6f 63 65 6c 6c 61 74 65 } //1 %Swindling26%\biocellate
		$a_81_1 = {5c 61 73 74 72 6f 6c 6f 67 69 5c 41 62 73 6f 72 62 65 66 61 63 69 65 6e 74 5c 66 75 6c 64 73 6b 61 65 67 } //1 \astrologi\Absorbefacient\fuldskaeg
		$a_81_2 = {73 61 67 73 67 65 72 65 6e 20 63 61 6e 65 74 74 65 } //1 sagsgeren canette
		$a_81_3 = {67 65 6e 75 69 6e 65 6e 65 73 73 65 73 } //1 genuinenesses
		$a_81_4 = {73 6b 6f 76 72 61 6e 6b 65 6e 73 20 69 6e 64 69 76 69 64 66 69 6c } //1 skovrankens individfil
		$a_81_5 = {6d 65 64 69 6f 66 72 6f 6e 74 61 6c 2e 65 78 65 } //1 mediofrontal.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}