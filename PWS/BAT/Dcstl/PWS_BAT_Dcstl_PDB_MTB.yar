
rule PWS_BAT_Dcstl_PDB_MTB{
	meta:
		description = "PWS:BAT/Dcstl.PDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {21 52 26 2e 43 3d 90 01 03 7c 2a 33 bf ba 84 9b c0 4f 0d d1 58 90 00 } //2
		$a_01_1 = {f6 c5 cc 67 6a 55 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}