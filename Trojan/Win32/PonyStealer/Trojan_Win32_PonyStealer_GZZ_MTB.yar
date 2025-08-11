
rule Trojan_Win32_PonyStealer_GZZ_MTB{
	meta:
		description = "Trojan:Win32/PonyStealer.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 00 19 01 00 42 00 21 fe f3 00 00 6c 74 } //5
		$a_01_1 = {31 11 d1 22 14 1d 94 4d } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}