
rule Trojan_Win32_Emotet_DO{
	meta:
		description = "Trojan:Win32/Emotet.DO,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {47 57 45 47 23 23 52 45 68 } //1 GWEG##REh
		$a_01_1 = {48 52 57 48 77 57 45 67 77 72 67 77 2e 70 64 62 } //1 HRWHwWEgwrgw.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}