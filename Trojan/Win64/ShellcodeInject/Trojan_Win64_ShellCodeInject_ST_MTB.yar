
rule Trojan_Win64_ShellCodeInject_ST_MTB{
	meta:
		description = "Trojan:Win64/ShellCodeInject.ST!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f be 04 01 48 8b 4c 24 20 48 8b 54 24 40 48 03 d1 48 8b ca 0f b6 09 33 c8 8b c1 48 8b 4c 24 20 48 8b 54 24 40 48 03 d1 48 8b ca 88 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}