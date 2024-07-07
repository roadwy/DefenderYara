
rule Trojan_Win32_Bunitu_VDSK_MTB{
	meta:
		description = "Trojan:Win32/Bunitu.VDSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 75 f8 33 f2 8b d6 8b ca b8 89 dc 00 00 03 c1 2d 89 dc 00 00 89 45 fc a1 90 01 04 8b 4d fc 89 08 90 00 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}