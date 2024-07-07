
rule Trojan_Win32_Obfuscator_OP_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.OP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {30 04 3e 4e 0f 90 01 05 8b 8d 90 01 04 5f 5e 33 cd 5b e8 90 01 04 81 c5 90 01 04 c9 c3 55 8d 6c 24 88 81 ec 90 01 04 a1 90 01 04 33 c5 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}