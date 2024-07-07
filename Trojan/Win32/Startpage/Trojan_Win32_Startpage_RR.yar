
rule Trojan_Win32_Startpage_RR{
	meta:
		description = "Trojan:Win32/Startpage.RR,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {6d 61 70 70 69 6e 67 5f 68 6b 5f 63 6e 74 72 5f } //2 mapping_hk_cntr_
		$a_01_1 = {7e 6a 61 6b 65 31 39 38 30 } //3 ~jake1980
		$a_01_2 = {6a 00 73 00 63 00 6f 00 6e 00 73 00 6f 00 6c 00 65 00 2e 00 64 00 6c 00 6c 00 } //2 jsconsole.dll
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2) >=7
 
}