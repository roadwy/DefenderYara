
rule Worm_Win32_Wadnock_gen_A{
	meta:
		description = "Worm:Win32/Wadnock.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0a 00 16 00 00 06 00 "
		
	strings :
		$a_03_0 = {eb 20 6a 10 8d 44 24 04 50 6a 00 6a 64 8d 44 24 20 50 53 e8 90 01 02 ff ff 68 2c 01 00 00 e8 90 01 02 ff ff 80 3d 90 01 04 00 75 d7 90 00 } //06 00 
		$a_03_1 = {74 26 83 fe 01 75 0f ba 75 08 00 00 8b 45 fc e8 90 01 04 eb 12 83 fe 02 75 0d ba 00 06 00 00 8b 45 fc e8 90 00 } //01 00 
		$a_00_2 = {23 20 53 79 73 74 65 6d 20 48 6f 73 74 73 20 46 69 6c 65 } //01 00  # System Hosts File
		$a_00_3 = {23 20 44 4f 20 4e 4f 54 20 52 45 4d 4f 56 45 20 49 54 20 21 } //01 00  # DO NOT REMOVE IT !
		$a_00_4 = {21 55 44 50 2e 44 44 4f 53 } //01 00  !UDP.DDOS
		$a_00_5 = {21 50 52 4f 43 2e 4b 49 4c 4c } //01 00  !PROC.KILL
		$a_00_6 = {21 41 44 44 2e 44 4e 53 46 41 4b 45 } //01 00  !ADD.DNSFAKE
		$a_00_7 = {21 52 55 4e } //01 00  !RUN
		$a_00_8 = {21 55 52 4c 2e 44 4f 57 4e 4c 4f 41 44 } //01 00  !URL.DOWNLOAD
		$a_00_9 = {21 55 50 44 41 54 45 } //01 00  !UPDATE
		$a_00_10 = {21 41 46 54 50 2e 43 4f 4e 46 49 47 } //01 00  !AFTP.CONFIG
		$a_00_11 = {21 55 52 4c 2e 53 50 4f 4f 46 } //01 00  !URL.SPOOF
		$a_00_12 = {63 6f 75 6e 74 65 72 2e 70 68 70 3f 61 63 74 69 6f 6e 3d 6b 6e 6f 63 6b } //01 00  counter.php?action=knock
		$a_00_13 = {21 70 72 6f 63 2e 6b 69 6c 6c 2e 2a 20 66 74 70 2e 65 78 65 } //01 00  !proc.kill.* ftp.exe
		$a_00_14 = {21 70 72 6f 63 2e 6b 69 6c 6c 2e 2a 20 74 66 74 70 2e 65 78 65 } //01 00  !proc.kill.* tftp.exe
		$a_00_15 = {21 70 72 6f 63 2e 6b 69 6c 6c 2e 2a 20 6e 68 2e 65 78 65 } //01 00  !proc.kill.* nh.exe
		$a_00_16 = {21 70 72 6f 63 2e 6b 69 6c 6c 2e 2a 20 6e 65 74 68 6f 73 74 2e 65 78 65 } //01 00  !proc.kill.* nethost.exe
		$a_00_17 = {21 70 72 6f 63 2e 6b 69 6c 6c 2e 2a 20 73 79 73 68 6f 73 74 2e 65 78 65 } //01 00  !proc.kill.* syshost.exe
		$a_00_18 = {21 70 72 6f 63 2e 6b 69 6c 6c 2e 2a 20 70 70 63 2e 65 78 65 } //01 00  !proc.kill.* ppc.exe
		$a_00_19 = {21 70 72 6f 63 2e 6b 69 6c 6c 2e 2a 20 70 61 79 74 69 6d 65 2e 65 78 65 } //01 00  !proc.kill.* paytime.exe
		$a_00_20 = {21 70 72 6f 63 2e 6b 69 6c 6c 2e 2a 20 6c 70 33 6d 72 31 73 68 2e 65 78 65 } //01 00  !proc.kill.* lp3mr1sh.exe
		$a_00_21 = {21 70 72 6f 63 2e 6b 69 6c 6c 2e 2a 20 74 69 62 73 2e 65 78 65 } //00 00  !proc.kill.* tibs.exe
	condition:
		any of ($a_*)
 
}