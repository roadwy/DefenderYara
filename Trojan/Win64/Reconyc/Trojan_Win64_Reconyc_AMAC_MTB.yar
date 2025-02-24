
rule Trojan_Win64_Reconyc_AMAC_MTB{
	meta:
		description = "Trojan:Win64/Reconyc.AMAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_80_0 = {73 61 6d 65 63 6f 6e 63 65 6e 74 72 61 74 65 2e 65 78 65 } //sameconcentrate.exe  10
		$a_80_1 = {77 65 78 74 72 61 63 74 2e 70 64 62 } //wextract.pdb  1
		$a_80_2 = {52 45 42 4f 4f 54 } //REBOOT  1
		$a_80_3 = {44 65 63 72 79 70 74 46 69 6c 65 41 } //DecryptFileA  1
		$a_80_4 = {6d 73 64 6f 77 6e 6c 64 2e 74 6d 70 } //msdownld.tmp  1
		$a_80_5 = {43 3a 5c 54 45 4d 50 5c 49 58 50 30 30 30 2e 54 4d 50 5c } //C:\TEMP\IXP000.TMP\  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=15
 
}