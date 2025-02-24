
rule Trojan_Win32_SmokeLoader_SZXB_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.SZXB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 c0 46 89 44 24 14 83 6c 24 14 0a 83 6c 24 14 3c 8a 44 24 14 30 04 1f 47 3b fd 7c } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}