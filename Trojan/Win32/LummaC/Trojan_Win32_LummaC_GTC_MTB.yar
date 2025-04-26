
rule Trojan_Win32_LummaC_GTC_MTB{
	meta:
		description = "Trojan:Win32/LummaC.GTC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {40 00 00 e0 2e 72 73 72 63 00 00 00 68 06 00 00 00 60 00 00 00 08 00 00 00 32 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 } //10
		$a_80_1 = {64 65 66 4f 66 66 2e 65 78 65 } //defOff.exe  1
	condition:
		((#a_01_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}