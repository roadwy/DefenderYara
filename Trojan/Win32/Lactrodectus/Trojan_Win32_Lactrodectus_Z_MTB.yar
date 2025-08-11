
rule Trojan_Win32_Lactrodectus_Z_MTB{
	meta:
		description = "Trojan:Win32/Lactrodectus.Z!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {f8 2b 75 0f b8 3e 00 00 00 66 89 44 24 24 e9 89 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}