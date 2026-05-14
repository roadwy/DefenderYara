
rule Trojan_Win64_Cryptinject_YBG_MTB{
	meta:
		description = "Trojan:Win64/Cryptinject.YBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 8d 40 80 0f b6 0a 41 2a c8 41 ff c0 32 c8 88 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}