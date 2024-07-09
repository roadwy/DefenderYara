
rule Trojan_Win32_Emotet_PDX_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PDX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8d 4c 24 ?? 45 c7 84 24 ?? ?? ?? ?? ff ff ff ff 0f b6 94 14 ?? ?? ?? ?? 30 55 } //1
		$a_81_1 = {57 31 6e 35 53 72 66 56 65 47 4d 4d 65 70 76 33 46 67 4f 78 49 73 37 6d 36 4d 70 6a 51 4a 71 77 67 70 62 6f 4b 32 46 70 4a } //1 W1n5SrfVeGMMepv3FgOxIs7m6MpjQJqwgpboK2FpJ
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}