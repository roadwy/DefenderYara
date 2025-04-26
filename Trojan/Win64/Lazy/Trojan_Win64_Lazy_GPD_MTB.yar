
rule Trojan_Win64_Lazy_GPD_MTB{
	meta:
		description = "Trojan:Win64/Lazy.GPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c6 45 fc 01 0f b7 c8 66 2b ca 66 31 4c 45 d0 48 ff c0 48 83 f8 15 72 ec c6 45 fc 00 48 8d 45 d0 49 c7 c0 ff ff ff ff 49 ff c0 66 42 83 3c 40 00 75 f5 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}