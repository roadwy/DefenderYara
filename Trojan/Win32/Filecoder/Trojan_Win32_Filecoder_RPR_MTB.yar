
rule Trojan_Win32_Filecoder_RPR_MTB{
	meta:
		description = "Trojan:Win32/Filecoder.RPR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 00 6a 00 6a 00 ff 15 90 01 04 8d 54 24 40 52 6a 00 ff 15 90 01 04 33 c0 8d 54 24 3c 52 50 50 50 50 89 44 24 24 ff 15 90 01 04 6a 00 6a 00 6a 00 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}