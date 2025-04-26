
rule Trojan_Win32_Sirefef_CD{
	meta:
		description = "Trojan:Win32/Sirefef.CD,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {38 30 30 30 30 30 63 62 2e 40 } //1 800000cb.@
		$a_01_1 = {81 fb 41 50 33 32 75 0b 8b 5e 04 83 fb 18 72 03 8b 46 10 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}