
rule Trojan_Win32_Pofims_B_{
	meta:
		description = "Trojan:Win32/Pofims.B!!Pofims.gen!dha,SIGNATURE_TYPE_ARHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 50 6a fe 68 60 24 3e 02 64 ff 35 00 00 00 00 a1 40 60 3e 02 33 c4 50 8d 44 24 04 64 a3 00 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}