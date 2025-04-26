
rule Trojan_BAT_AsyncRat_AE_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 d4 02 e8 c9 0f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 31 00 00 00 17 00 00 00 58 00 00 00 9e } //2
		$a_01_1 = {73 65 72 76 65 72 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 server.Resources.resources
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}
rule Trojan_BAT_AsyncRat_AE_MTB_2{
	meta:
		description = "Trojan:BAT/AsyncRat.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {77 63 76 7a 6c 6d 38 70 77 64 70 73 62 75 79 78 36 34 33 33 35 6c 68 7a 74 32 6d 7a 66 71 32 37 } //1 wcvzlm8pwdpsbuyx64335lhzt2mzfq27
		$a_01_1 = {36 78 76 6b 39 70 79 35 35 39 6d 7a 6c 79 64 6a 77 67 38 37 36 66 72 71 36 32 73 6d 33 73 66 62 } //1 6xvk9py559mzlydjwg876frq62sm3sfb
		$a_01_2 = {74 65 78 6b 77 34 6c 33 73 77 71 64 7a 64 79 76 70 6a 79 68 63 79 79 68 73 6d 74 38 38 6e 61 7a } //1 texkw4l3swqdzdyvpjyhcyyhsmt88naz
		$a_01_3 = {64 74 32 66 65 72 6d 77 76 33 79 79 6c 35 70 6c 76 38 35 77 34 78 67 75 7a 6d 61 36 73 6d 36 76 } //1 dt2fermwv3yyl5plv85w4xguzma6sm6v
		$a_01_4 = {38 6b 35 75 35 38 36 78 6b 68 65 73 68 72 32 64 74 72 64 74 61 32 67 63 75 6b 76 67 32 78 73 73 } //1 8k5u586xkheshr2dtrdta2gcukvg2xss
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}