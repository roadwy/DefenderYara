
rule Trojan_Win32_Tnega_F_MTB{
	meta:
		description = "Trojan:Win32/Tnega.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {68 d8 85 40 00 5b 81 e9 90 01 04 e8 90 01 04 31 1f 47 09 ce 39 d7 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}