
rule Trojan_Win32_Remcos_RD_MTB{
	meta:
		description = "Trojan:Win32/Remcos.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {85 c0 85 c0 83 f6 90 01 01 8b 1c 0f 66 3d 90 01 02 66 3d 90 01 02 66 3d 90 01 02 83 f6 90 01 01 83 f6 90 01 01 66 3d 90 01 02 66 3d 90 01 02 66 3d 90 01 02 31 c3 66 3d 90 01 02 83 f6 90 01 01 66 3d 90 01 02 83 f6 90 01 01 85 c0 83 f6 90 01 01 53 83 f6 90 01 01 85 c0 66 3d 90 01 02 83 f6 90 01 01 8f 04 0f 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}