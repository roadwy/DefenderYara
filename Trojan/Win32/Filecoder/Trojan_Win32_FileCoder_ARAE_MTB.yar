
rule Trojan_Win32_FileCoder_ARAE_MTB{
	meta:
		description = "Trojan:Win32/FileCoder.ARAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 04 30 30 04 1f ff 46 40 47 8b 46 40 3b 7d 08 72 dc } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}