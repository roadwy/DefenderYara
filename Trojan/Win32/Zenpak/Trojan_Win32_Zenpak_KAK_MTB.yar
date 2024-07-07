
rule Trojan_Win32_Zenpak_KAK_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.KAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6f 72 65 65 75 78 61 6e 61 69 } //1 oreeuxanai
		$a_01_1 = {42 6b 65 6e 4c 6f 61 64 69 61 61 65 65 } //1 BkenLoadiaaee
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}