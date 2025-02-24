
rule Trojan_Win64_DllInject_GB_MTB{
	meta:
		description = "Trojan:Win64/DllInject.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 03 c2 48 c1 e8 04 48 6b c0 19 48 2b c8 49 0f af cb 8a 44 0c 20 42 32 04 17 41 88 02 49 ff c2 44 3b cb 72 bf } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}