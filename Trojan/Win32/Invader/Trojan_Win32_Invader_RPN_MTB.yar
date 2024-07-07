
rule Trojan_Win32_Invader_RPN_MTB{
	meta:
		description = "Trojan:Win32/Invader.RPN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 3c 81 8b 3d 90 01 04 03 3d 90 01 04 89 3d 90 01 04 8b 0d 90 01 04 8b 1d 90 01 04 31 cb 8b 35 90 01 04 01 de 81 c6 90 01 04 89 35 90 01 04 8b 35 90 01 04 31 d6 0f af 35 90 01 04 89 35 90 01 04 8b 35 90 01 04 31 35 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}