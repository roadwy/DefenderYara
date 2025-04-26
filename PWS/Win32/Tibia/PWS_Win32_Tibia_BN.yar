
rule PWS_Win32_Tibia_BN{
	meta:
		description = "PWS:Win32/Tibia.BN,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 3d 00 00 74 69 62 69 61 2e 63 6f 6d 00 00 00 61 70 70 64 } //5
		$a_01_1 = {5c 76 6d 72 65 67 2e 65 78 65 } //2 \vmreg.exe
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2) >=7
 
}