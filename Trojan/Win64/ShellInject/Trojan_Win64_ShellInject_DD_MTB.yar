
rule Trojan_Win64_ShellInject_DD_MTB{
	meta:
		description = "Trojan:Win64/ShellInject.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b d0 41 88 48 0d 4c 8b c3 0f b6 4f 0f 32 0f 48 83 38 0f 76 [0-04] 4c 8b 03 41 88 48 0e 48 8b cb 0f b6 47 10 32 07 48 83 3a 0f 76 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}