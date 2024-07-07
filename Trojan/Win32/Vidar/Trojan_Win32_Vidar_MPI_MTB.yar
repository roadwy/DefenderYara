
rule Trojan_Win32_Vidar_MPI_MTB{
	meta:
		description = "Trojan:Win32/Vidar.MPI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d f0 03 fa d3 ea 89 55 f8 8b 45 c8 01 45 f8 8b 45 f8 33 c7 31 45 fc 89 35 0c fa 42 00 8b 45 f4 89 45 e4 8b 45 fc 29 45 e4 8b 45 e4 89 45 f4 8d 45 e0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}