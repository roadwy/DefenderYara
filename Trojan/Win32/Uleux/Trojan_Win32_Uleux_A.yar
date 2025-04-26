
rule Trojan_Win32_Uleux_A{
	meta:
		description = "Trojan:Win32/Uleux.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 41 68 6e 4c 61 62 5c 56 33 4c 69 74 65 33 30 5c 55 6e 69 6e 73 74 2e 65 78 65 } //1 C:\Program Files\AhnLab\V3Lite30\Uninst.exe
		$a_01_1 = {7b 34 66 36 34 35 32 32 30 2d 33 30 36 64 2d 31 31 64 32 2d 39 39 35 64 2d 30 30 63 30 34 66 39 38 62 62 63 39 7d } //1 {4f645220-306d-11d2-995d-00c04f98bbc9}
		$a_01_2 = {73 6e 69 66 66 65 72 2e 64 64 6e 73 2e 69 6e 66 6f } //1 sniffer.ddns.info
		$a_01_3 = {70 72 6f 63 4d 65 6d 62 65 72 4c 6f 67 69 6e } //1 procMemberLogin
		$a_01_4 = {4c 6f 67 69 6e 5f 50 72 6f 63 2e 61 73 70 } //1 Login_Proc.asp
		$a_01_5 = {6d 62 5f 70 61 73 73 77 6f 72 64 } //1 mb_password
		$a_01_6 = {53 5f 54 5f 41 5f 52 5f 54 5f 53 5f 4e 5f 49 5f 46 5f 46 5f 45 5f 52 5f 21 5f 40 5f 40 5f 21 } //1 S_T_A_R_T_S_N_I_F_F_E_R_!_@_@_!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}