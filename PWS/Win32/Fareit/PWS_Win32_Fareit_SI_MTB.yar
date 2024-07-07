
rule PWS_Win32_Fareit_SI_MTB{
	meta:
		description = "PWS:Win32/Fareit.SI!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 0b 85 ff 66 81 ff d3 c7 eb 03 00 00 00 83 c2 04 66 81 fb f7 9a 3d a3 a2 5f 1e eb 08 00 00 00 00 00 00 00 00 83 c7 04 66 3d 0f f5 66 81 fb 22 65 eb 09 00 00 00 00 00 00 00 00 00 81 fa f4 b9 00 00 74 28 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}