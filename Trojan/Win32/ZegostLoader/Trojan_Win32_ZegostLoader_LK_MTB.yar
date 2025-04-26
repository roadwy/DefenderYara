
rule Trojan_Win32_ZegostLoader_LK_MTB{
	meta:
		description = "Trojan:Win32/ZegostLoader.LK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 b9 2f 04 90 80 2c 11 05 90 90 90 e2 f7 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}