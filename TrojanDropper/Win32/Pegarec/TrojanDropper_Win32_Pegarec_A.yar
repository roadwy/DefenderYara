
rule TrojanDropper_Win32_Pegarec_A{
	meta:
		description = "TrojanDropper:Win32/Pegarec.A,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {65 00 20 00 2d 00 6f 00 2b 00 20 00 2d 00 72 00 20 00 2d 00 69 00 6e 00 75 00 6c 00 20 00 [0-20] 2e 00 6a 00 70 00 67 00 20 00 [0-20] 2e 00 65 00 78 00 65 00 20 00 26 00 20 00 90 1b 01 2e 00 65 00 78 00 65 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}