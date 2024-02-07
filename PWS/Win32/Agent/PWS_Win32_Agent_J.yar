
rule PWS_Win32_Agent_J{
	meta:
		description = "PWS:Win32/Agent.J,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 65 72 76 65 72 2e 64 6c 6c 00 52 75 6b 6f 75 } //01 00  敓癲牥搮汬刀歵畯
		$a_00_1 = {77 69 6e 73 74 61 30 00 73 68 69 74 } //01 00  楷獮慴0桳瑩
		$a_00_2 = {5c 58 6c 6f 67 2e 64 61 74 } //01 00  \Xlog.dat
		$a_01_3 = {44 4e 41 4d 4d 4f 43 5c 4e 45 50 4f 5c 4c 4c 45 48 53 5c 45 58 45 2e 45 52 4f 4c 50 58 45 49 5c 53 4e 4f 49 54 41 43 49 4c 50 50 61 } //01 00  DNAMMOC\NEPO\LLEHS\EXE.EROLPXEI\SNOITACILPPa
		$a_01_4 = {2d 2f 2d 20 2d 2f 2d 00 00 61 76 61 73 74 00 00 00 61 76 69 72 61 } //01 00 
		$a_03_5 = {5c 53 69 6e 63 65 00 90 09 08 00 53 4f 46 54 57 41 52 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}