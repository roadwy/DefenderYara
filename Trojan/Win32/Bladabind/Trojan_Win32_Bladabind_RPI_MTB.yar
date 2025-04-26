
rule Trojan_Win32_Bladabind_RPI_MTB{
	meta:
		description = "Trojan:Win32/Bladabind.RPI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 01 81 c1 04 00 00 00 09 df 39 f1 75 ed } //1
		$a_03_1 = {31 03 81 ee ?? ?? ?? ?? 81 c3 04 00 00 00 39 d3 75 e9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}