
rule Trojan_Win32_Lazy_GPPC_MTB{
	meta:
		description = "Trojan:Win32/Lazy.GPPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 41 b4 30 44 0d a0 48 ff c1 48 83 f9 3f 72 f0 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}