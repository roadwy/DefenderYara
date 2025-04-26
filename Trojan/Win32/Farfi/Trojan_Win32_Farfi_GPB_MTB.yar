
rule Trojan_Win32_Farfi_GPB_MTB{
	meta:
		description = "Trojan:Win32/Farfi.GPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 c9 89 c8 31 d2 f7 f6 0f b6 04 17 30 04 0b 83 c1 01 3b 4d } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}