
rule Backdoor_Win32_Sodager_B{
	meta:
		description = "Backdoor:Win32/Sodager.B,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {75 5f 72 6f 74 61 73 5f 73 71 75 69 64 } //3 u_rotas_squid
		$a_01_1 = {54 4e 44 62 53 62 7a 6d 53 63 4c 63 41 32 39 6b 50 4e 48 74 52 74 39 68 42 64 31 6f 52 74 58 76 42 63 35 72 54 36 7a 5a 52 73 76 63 51 4d 54 56 54 4e 39 69 38 59 6d 57 38 57 } //4 TNDbSbzmScLcA29kPNHtRt9hBd1oRtXvBc5rT6zZRsvcQMTVTN9i8YmW8W
		$a_01_2 = {20 3c 3c 2d 2d 2d 2d 20 41 6c 69 20 6f 20 4c 49 6e 6b 20 64 6f 20 73 69 67 61 2d 6d 65 2e 74 78 74 } //3  <<---- Ali o LInk do siga-me.txt
		$a_03_3 = {38 36 50 66 53 63 4c 74 4f 4d 6e 69 38 36 35 61 50 32 31 58 52 36 6e 6c 54 73 4c 61 53 37 39 6c 50 74 39 58 52 49 30 62 47 4c 31 47 48 34 35 4b 47 49 4c 53 49 71 39 49 45 90 02 20 50 4e 58 62 38 35 39 47 47 71 44 33 90 00 } //3
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*4+(#a_01_2  & 1)*3+(#a_03_3  & 1)*3) >=10
 
}