
rule Trojan_Win32_Zopt_A{
	meta:
		description = "Trojan:Win32/Zopt.A,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0a 00 07 00 00 "
		
	strings :
		$a_01_0 = {62 72 75 6d 61 6d 6b 63 77 67 72 6d 2e 62 72 75 6d 61 6d 6b 63 77 67 72 6d } //2 brumamkcwgrm.brumamkcwgrm
		$a_01_1 = {69 78 6e 66 70 6c 73 72 } //1 ixnfplsr
		$a_01_2 = {32 30 46 30 38 44 31 44 2d 31 30 46 31 2d 34 45 45 42 2d 42 46 32 37 2d 41 42 43 34 35 45 37 45 37 36 31 44 } //2 20F08D1D-10F1-4EEB-BF27-ABC45E7E761D
		$a_01_3 = {46 39 34 38 35 39 46 44 2d 38 41 43 45 2d 34 44 32 37 2d 42 35 38 42 2d 45 35 42 43 37 39 34 30 38 43 46 46 } //2 F94859FD-8ACE-4D27-B58B-E5BC79408CFF
		$a_01_4 = {6e 71 77 76 64 67 6b 64 7a 6b 75 42 73 30 69 78 6e 66 70 6c 73 72 } //2 nqwvdgkdzkuBs0ixnfplsr
		$a_01_5 = {41 64 6d 69 6e 69 73 74 72 61 74 6f 72 5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 43 4c 49 45 4e 54 } //2 Administrator\Application DataCLIENT
		$a_01_6 = {69 6d 70 65 6e 63 } //1 impenc
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*1) >=10
 
}
rule Trojan_Win32_Zopt_A_2{
	meta:
		description = "Trojan:Win32/Zopt.A,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0c 00 07 00 00 "
		
	strings :
		$a_01_0 = {61 64 66 61 6d 6b 63 77 70 72 2e 61 64 66 61 6d 6b 63 77 70 72 } //2 adfamkcwpr.adfamkcwpr
		$a_01_1 = {7b 32 37 44 41 45 33 33 35 2d 35 38 39 32 2d 34 44 39 45 2d 39 32 31 30 2d 39 41 45 32 37 31 37 41 46 41 41 42 7d } //2 {27DAE335-5892-4D9E-9210-9AE2717AFAAB}
		$a_01_2 = {63 68 6b 61 6d 6b 63 77 68 73 74 2e 63 68 6b 61 6d 6b 63 77 68 73 74 } //2 chkamkcwhst.chkamkcwhst
		$a_01_3 = {7b 41 31 46 42 31 42 35 45 2d 37 31 31 31 2d 34 34 45 44 2d 42 34 30 32 2d 45 41 39 32 39 43 44 33 33 44 39 41 7d } //2 {A1FB1B5E-7111-44ED-B402-EA929CD33D9A}
		$a_01_4 = {6e 71 77 76 64 67 6b 64 7a 6b 6f 6f 73 74 73 35 69 78 6e 66 70 6c 73 72 } //2 nqwvdgkdzkoosts5ixnfplsr
		$a_01_5 = {63 61 6c 6c 6d 74 68 64 } //2 callmthd
		$a_01_6 = {41 64 6d 69 6e 69 73 74 72 61 74 6f 72 5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 43 4c 49 45 4e 54 } //2 Administrator\Application DataCLIENT
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2) >=12
 
}