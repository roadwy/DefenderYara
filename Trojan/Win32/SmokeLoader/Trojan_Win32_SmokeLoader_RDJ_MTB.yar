
rule Trojan_Win32_SmokeLoader_RDJ_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.RDJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 75 e4 8b 45 d4 31 45 f8 33 75 f8 81 3d } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}