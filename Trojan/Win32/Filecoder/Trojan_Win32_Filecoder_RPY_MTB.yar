
rule Trojan_Win32_Filecoder_RPY_MTB{
	meta:
		description = "Trojan:Win32/Filecoder.RPY!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 06 32 c2 88 07 46 47 49 83 f9 00 e9 dc ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}