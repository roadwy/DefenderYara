
rule Trojan_Win32_Zusy_BAB_MTB{
	meta:
		description = "Trojan:Win32/Zusy.BAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {1b c0 53 83 e0 02 0c 20 50 6a 02 53 6a 01 68 ?? ?? ?? ?? ff 75 08 ff 15 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}