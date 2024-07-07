
rule Worm_Win32_Cosmu_B{
	meta:
		description = "Worm:Win32/Cosmu.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {54 41 50 49 78 46 6f 72 6d } //1 TAPIxForm
		$a_00_1 = {73 65 74 20 53 45 52 3d 66 74 70 2e 73 61 6b 75 6e 69 61 } //1 set SER=ftp.sakunia
		$a_00_2 = {3e 3e 20 75 70 6c 2e 74 78 74 } //1 >> upl.txt
		$a_02_3 = {2e 6a 70 67 2e 65 78 65 00 00 66 3a 2f 90 02 10 2e 6a 70 67 2e 65 78 65 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}