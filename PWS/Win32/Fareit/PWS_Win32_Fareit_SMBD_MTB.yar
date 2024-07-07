
rule PWS_Win32_Fareit_SMBD_MTB{
	meta:
		description = "PWS:Win32/Fareit.SMBD!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b7 14 71 8d 7a bf 83 ff 19 0f 87 03 00 00 00 83 c2 20 66 89 14 71 46 3b f0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}