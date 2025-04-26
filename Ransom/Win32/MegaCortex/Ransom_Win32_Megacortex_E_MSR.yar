
rule Ransom_Win32_Megacortex_E_MSR{
	meta:
		description = "Ransom:Win32/Megacortex.E!MSR,SIGNATURE_TYPE_PEHSTR,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {2e 00 6d 00 65 00 67 00 61 00 63 00 30 00 72 00 74 00 78 00 } //1 .megac0rtx
		$a_01_1 = {2e 00 6d 00 33 00 67 00 61 00 63 00 30 00 72 00 74 00 78 00 } //1 .m3gac0rtx
		$a_01_2 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 } //1 vssadmin delete shadows
		$a_01_3 = {25 00 31 00 25 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 61 00 6c 00 6c 00 20 00 2f 00 71 00 75 00 69 00 65 00 74 00 } //1 %1% delete shadows /all /quiet
		$a_01_4 = {69 6e 66 65 63 74 65 64 20 77 69 74 68 20 4d 65 67 61 43 6f 72 74 65 78 20 4d 61 6c 77 61 72 65 } //1 infected with MegaCortex Malware
		$a_01_5 = {77 65 27 76 65 20 68 61 63 6b 65 64 20 79 6f 75 72 20 63 6f 72 70 6f 72 61 74 65 20 6e 65 74 77 6f 72 6b } //1 we've hacked your corporate network
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=3
 
}