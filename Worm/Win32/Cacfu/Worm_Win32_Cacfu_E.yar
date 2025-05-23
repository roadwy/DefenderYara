
rule Worm_Win32_Cacfu_E{
	meta:
		description = "Worm:Win32/Cacfu.E,SIGNATURE_TYPE_PEHSTR,1f 00 1f 00 05 00 00 "
		
	strings :
		$a_01_0 = {00 00 74 65 6c 2e 78 6c 73 00 45 78 63 65 6c 00 00 b9 a4 b3 cc 31 00 00 } //10
		$a_01_1 = {53 00 51 00 4c 00 4f 00 4c 00 45 00 44 00 42 00 2e 00 31 00 } //10 SQLOLEDB.1
		$a_01_2 = {49 00 6e 00 74 00 65 00 67 00 72 00 61 00 74 00 65 00 64 00 20 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 3d 00 53 00 53 00 50 00 49 00 3b 00 } //10 Integrated Security=SSPI;
		$a_01_3 = {2e 00 64 00 62 00 6f 00 2e 00 67 00 6c 00 5f 00 61 00 63 00 63 00 73 00 75 00 6d 00 20 00 77 00 68 00 65 00 72 00 65 00 20 00 69 00 70 00 65 00 72 00 69 00 6f 00 64 00 3d 00 } //1 .dbo.gl_accsum where iperiod=
		$a_01_4 = {73 00 65 00 6c 00 65 00 63 00 74 00 20 00 69 00 79 00 65 00 61 00 72 00 20 00 66 00 72 00 6f 00 6d 00 20 00 75 00 61 00 5f 00 70 00 65 00 72 00 69 00 6f 00 64 00 20 00 77 00 68 00 65 00 72 00 65 00 20 00 63 00 41 00 63 00 63 00 5f 00 69 00 64 00 3d 00 } //1 select iyear from ua_period where cAcc_id=
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=31
 
}