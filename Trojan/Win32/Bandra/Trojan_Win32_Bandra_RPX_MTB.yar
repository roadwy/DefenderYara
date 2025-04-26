
rule Trojan_Win32_Bandra_RPX_MTB{
	meta:
		description = "Trojan:Win32/Bandra.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4f 89 4c 24 28 8b 31 03 f2 8a 16 46 88 54 24 0f 84 d2 8b 50 18 } //1
		$a_01_1 = {31 39 34 2e 31 36 39 2e 31 37 35 2e 31 32 38 } //1 194.169.175.128
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}