
rule Trojan_Win32_Emotet_DCR_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DCR!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 c2 99 f7 fb 0f b6 04 32 8b 54 24 24 0f be 54 0a ff 8a d8 f6 d2 f6 d3 0a da 8b 54 24 24 0f be 54 0a ff 0a c2 22 d8 83 6c 24 10 01 88 59 ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}