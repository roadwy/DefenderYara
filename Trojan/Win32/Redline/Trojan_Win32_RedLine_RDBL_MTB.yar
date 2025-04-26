
rule Trojan_Win32_RedLine_RDBL_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RDBL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 d7 c1 c0 01 87 d1 2b f0 2b 35 c9 3e 5f 00 03 c8 03 1d 07 3c 5f 00 31 05 ed 37 5f 00 0b 3d 42 3e 5f 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}