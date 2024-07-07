
rule Trojan_Win32_Masslogger_MR{
	meta:
		description = "Trojan:Win32/Masslogger.MR,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {c0 c1 02 b2 60 2a d0 02 ca f6 d1 80 f1 59 80 c1 20 c0 c9 02 f6 d1 d0 c9 f6 d1 80 e9 11 32 c8 f6 d9 88 88 90 02 04 40 3d 90 02 04 90 18 8a 88 90 00 } //1
		$a_02_1 = {74 27 fe c0 04 8f fe c8 2c 9e 2c 2f 2c 78 fe c8 04 85 fe c0 fe c8 fe c8 34 b9 2c 1e 04 e1 88 81 90 02 04 83 c1 01 90 18 8a 81 90 02 04 81 f9 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}