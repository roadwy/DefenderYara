
rule Trojan_Win32_Unruy_GZZ_MTB{
	meta:
		description = "Trojan:Win32/Unruy.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {53 0a 47 18 3a c8 04 08 64 46 34 fc ea 90 01 04 44 0e ee d2 75 14 90 00 } //5
		$a_01_1 = {ba 05 ac 3d 5c 30 10 40 49 0f 85 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}