
rule Trojan_Win32_Pterodo_YAC_MTB{
	meta:
		description = "Trojan:Win32/Pterodo.YAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 d0 8b 75 cc 01 f0 8b 4d e0 74 11 4e 8a 44 31 ff 84 c0 74 03 30 04 31 4e 39 f2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}