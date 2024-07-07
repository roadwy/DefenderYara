
rule Backdoor_BAT_QuasarRat_GG_MTB{
	meta:
		description = "Backdoor:BAT/QuasarRat.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 08 00 00 "
		
	strings :
		$a_81_0 = {43 6c 69 70 62 6f 61 72 64 } //1 Clipboard
		$a_81_1 = {58 44 61 74 61 20 53 6f 75 72 63 65 3d 57 54 46 42 45 45 2d 50 43 5c 53 51 4c 45 58 53 45 52 56 45 52 } //10 XData Source=WTFBEE-PC\SQLEXSERVER
		$a_81_2 = {73 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 51 4c 5f 4e 67 75 6f 69 44 75 6e 67 20 77 68 65 72 65 20 54 65 6e 44 61 6e 67 4e 68 61 70 } //1 select * from QL_NguoiDung where TenDangNhap
		$a_81_3 = {73 65 6c 65 63 74 20 6e 61 6d 65 20 46 72 6f 6d 20 73 79 73 2e 64 61 74 61 62 61 73 65 73 } //1 select name From sys.databases
		$a_81_4 = {50 61 73 73 77 6f 72 64 3d } //1 Password=
		$a_81_5 = {4c 54 57 4e 43 43 6f 6e 6e } //1 LTWNCConn
		$a_81_6 = {74 69 6e 79 75 72 6c 2e 63 6f 6d } //1 tinyurl.com
		$a_81_7 = {61 70 69 2e 62 69 74 2e 6c 79 } //1 api.bit.ly
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*10+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=16
 
}