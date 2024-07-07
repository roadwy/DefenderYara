
rule Trojan_WinNT_Regin_gen_B{
	meta:
		description = "Trojan:WinNT/Regin.gen.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {3b f0 72 dc 6a 03 57 68 90 01 04 e8 90 01 04 83 c4 0c 85 c0 75 04 c6 45 ff 01 90 00 } //1
		$a_01_1 = {c7 07 fe ba dc fe 89 47 04 } //1
		$a_01_2 = {c7 04 24 11 77 11 77 be 11 66 11 66 ff e0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}