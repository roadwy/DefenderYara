
rule Trojan_Win32_Razy_CW_MTB{
	meta:
		description = "Trojan:Win32/Razy.CW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 16 81 c6 01 00 00 00 09 ff 29 c9 39 c6 75 e2 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}