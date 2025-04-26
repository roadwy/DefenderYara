
rule Trojan_Win32_Cobaltstrike_AJS_MTB{
	meta:
		description = "Trojan:Win32/Cobaltstrike.AJS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 c9 03 ca 81 e1 ff 00 00 80 79 08 49 81 c9 00 ff ff ff 41 0f b6 4c 0c 0c 30 0c 28 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}