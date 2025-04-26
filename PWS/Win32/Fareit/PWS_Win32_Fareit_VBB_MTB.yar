
rule PWS_Win32_Fareit_VBB_MTB{
	meta:
		description = "PWS:Win32/Fareit.VBB!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0b ff ab 4a 0b ff ab 4a 0c ff ab 4a 0b ff ab 4a 0c ff ab 4a 0b ff ab 4a 0b ff ab 49 0c ff ab 4a 0b ff ab 4a 0c ff ab 4a 0b ff ab 4a 0b ff ab 4a 0c ff ab 4a 0b ff ab 4a 0c ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}