
rule Trojan_Win32_LummaC_ACLM_MTB{
	meta:
		description = "Trojan:Win32/LummaC.ACLM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 ca 83 e2 0a 8d 5a ff 83 e3 02 89 cf 83 e7 08 0f af df 89 d6 29 fa 83 f6 02 01 f2 89 ce 83 e6 02 0f af d6 89 ce 81 f6 ?? ?? ?? ?? 01 de 01 d6 0f b6 14 08 31 d6 89 75 f0 8b 55 f0 80 c2 c2 88 14 08 89 ca 81 f2 ?? ?? ?? ?? 89 ce 83 ce 01 21 d6 83 f1 01 8d 0c 71 83 f9 10 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}