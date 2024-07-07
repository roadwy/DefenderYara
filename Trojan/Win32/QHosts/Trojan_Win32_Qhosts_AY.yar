
rule Trojan_Win32_Qhosts_AY{
	meta:
		description = "Trojan:Win32/Qhosts.AY,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 70 2e 74 78 74 00 } //1
		$a_01_1 = {3a 34 35 36 31 32 2f 73 74 61 74 2f 74 75 6b 2f } //1 :45612/stat/tuk/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}