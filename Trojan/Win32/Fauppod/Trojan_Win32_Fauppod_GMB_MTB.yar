
rule Trojan_Win32_Fauppod_GMB_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.GMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 38 4a 8d 05 90 01 04 31 18 40 83 e8 03 31 35 90 01 04 31 d0 29 c2 89 2d 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}