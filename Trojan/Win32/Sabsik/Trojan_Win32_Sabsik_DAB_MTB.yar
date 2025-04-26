
rule Trojan_Win32_Sabsik_DAB_MTB{
	meta:
		description = "Trojan:Win32/Sabsik.DAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 08 81 e1 ff ff 00 00 c1 e1 02 01 ca 8b 3a 89 eb 81 c3 9b 00 00 00 8b 1b } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}