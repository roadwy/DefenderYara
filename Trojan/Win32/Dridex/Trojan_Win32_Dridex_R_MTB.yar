
rule Trojan_Win32_Dridex_R_MTB{
	meta:
		description = "Trojan:Win32/Dridex.R!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 d1 89 c8 99 f7 fe 8b 4d e0 8a 3c 11 8b 75 cc 88 3c 31 88 1c 11 0f b6 0c 31 01 f9 81 e1 ff 00 00 00 8b 7d e8 8b 75 d0 8a 1c 37 8b 75 e0 32 1c 0e 8b 4d e4 8b 75 d0 88 1c 31 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}