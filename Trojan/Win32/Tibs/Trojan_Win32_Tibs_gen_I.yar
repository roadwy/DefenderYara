
rule Trojan_Win32_Tibs_gen_I{
	meta:
		description = "Trojan:Win32/Tibs.gen!I,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {56 57 53 55 e8 00 00 00 00 5d 81 ed 90 01 01 2c 40 00 e8 e6 02 00 00 e8 b4 06 00 00 b8 00 00 00 00 85 c0 75 21 ff 85 90 01 01 2c 40 00 e8 8c 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}