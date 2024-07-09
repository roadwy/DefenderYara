
rule Trojan_Win32_Gearclop_gen_C{
	meta:
		description = "Trojan:Win32/Gearclop.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {24 0f c6 06 61 00 06 c1 c0 04 46 e2 f3 } //1
		$a_03_1 = {83 45 ec 03 83 45 f0 03 8d 45 e4 50 e8 ?? ?? ?? ?? 6a 64 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}