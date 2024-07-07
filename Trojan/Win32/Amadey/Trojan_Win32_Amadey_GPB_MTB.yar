
rule Trojan_Win32_Amadey_GPB_MTB{
	meta:
		description = "Trojan:Win32/Amadey.GPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 18 88 5d f3 8d 55 f3 52 8d 4d b0 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}