
rule Ransom_Win32_STOP_RP_MTB{
	meta:
		description = "Ransom:Win32/STOP.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {3d c3 01 00 00 75 06 8d 91 31 a2 00 00 81 fa 41 01 00 00 75 0c 89 90 01 04 00 89 90 01 04 00 40 3d 90 01 04 7c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}