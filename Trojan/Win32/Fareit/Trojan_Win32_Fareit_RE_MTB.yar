
rule Trojan_Win32_Fareit_RE_MTB{
	meta:
		description = "Trojan:Win32/Fareit.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {b5 cc 49 51 40 af 32 76 1b 46 92 f2 cc 1a fe 6a 02 72 84 } //01 00 
		$a_01_1 = {4c 00 6e 00 6b 00 6f 00 72 00 74 00 65 00 74 00 73 00 2e 00 65 00 78 00 65 00 } //00 00  Lnkortets.exe
	condition:
		any of ($a_*)
 
}