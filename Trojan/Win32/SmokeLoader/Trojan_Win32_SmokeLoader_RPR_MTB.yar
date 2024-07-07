
rule Trojan_Win32_SmokeLoader_RPR_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.RPR!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6a 00 6a 00 6a 00 e8 1f 14 00 00 68 58 14 40 00 6a 00 e8 f3 0f 00 00 6a 00 e8 9c 0f 00 00 6a 00 6a 00 e8 43 0d 00 00 e8 fe 0b 00 00 6a 00 e8 c7 0b 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}