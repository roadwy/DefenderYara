
rule Trojan_Win32_TrickBot_DSO_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.DSO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 c4 04 68 90 01 04 e8 90 01 04 83 c4 04 0f b6 84 33 90 02 04 30 84 1c 90 02 04 68 90 01 04 e8 90 01 04 83 c4 04 68 90 01 04 e8 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}