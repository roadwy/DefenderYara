
rule Trojan_Win32_GhostRat_NIM_MTB{
	meta:
		description = "Trojan:Win32/GhostRat.NIM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 83 30 60 83 c0 02 49 75 f6 } //1
		$a_01_1 = {64 a1 30 00 00 00 8b 40 0c 8b 70 1c ad 8b 40 08 8b f8 8b e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}