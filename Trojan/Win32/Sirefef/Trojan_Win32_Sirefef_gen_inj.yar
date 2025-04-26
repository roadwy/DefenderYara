
rule Trojan_Win32_Sirefef_gen_inj{
	meta:
		description = "Trojan:Win32/Sirefef.gen!inj,SIGNATURE_TYPE_ARHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {56 57 64 8b 35 30 00 00 00 8b 76 0c 8b 76 1c 8b 46 08 8b 7e 20 8b 36 80 3f 6b 75 f3 80 7f 18 00 75 ed 5f 5e } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}