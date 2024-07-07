
rule Trojan_Win32_Zusy_GPN_MTB{
	meta:
		description = "Trojan:Win32/Zusy.GPN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {da 80 b6 50 c8 01 10 c8 46 3b f7 7c f4 83 ec 10 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}