
rule Trojan_Win32_SmokeLoader_SP_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 c4 18 31 c0 5b c3 8d 76 00 c7 44 24 04 ff ff ff ff 8b 43 04 89 04 24 ff 15 d4 b1 42 00 83 ec 08 85 c0 74 db } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}