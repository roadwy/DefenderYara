
rule Trojan_Win32_Filecoder_RPX_MTB{
	meta:
		description = "Trojan:Win32/Filecoder.RPX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {ba 25 00 00 00 8a 06 90 32 c2 90 88 07 90 46 90 47 90 e9 c6 ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}