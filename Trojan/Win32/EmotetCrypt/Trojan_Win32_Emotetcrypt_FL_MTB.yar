
rule Trojan_Win32_Emotetcrypt_FL_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.FL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0b 00 00 0a 00 "
		
	strings :
		$a_81_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllRegisterServer
		$a_81_1 = {6a 69 36 66 79 68 37 65 68 35 2e 64 6c 6c } //01 00  ji6fyh7eh5.dll
		$a_81_2 = {6c 37 69 71 62 68 37 69 74 6f 34 68 68 70 64 72 63 30 70 } //01 00  l7iqbh7ito4hhpdrc0p
		$a_81_3 = {70 62 7a 74 66 7a 65 36 78 66 34 6e 76 6d 63 30 65 63 66 68 67 73 78 35 70 33 } //01 00  pbztfze6xf4nvmc0ecfhgsx5p3
		$a_81_4 = {72 63 39 74 76 70 63 70 73 32 78 34 64 63 79 71 65 67 7a 78 62 6e 63 71 65 68 31 6f } //01 00  rc9tvpcps2x4dcyqegzxbncqeh1o
		$a_81_5 = {79 6f 6f 61 69 30 77 6a 78 32 75 62 72 72 62 6e 35 76 6d 62 34 33 71 7a 62 35 71 70 } //01 00  yooai0wjx2ubrrbn5vmb43qzb5qp
		$a_81_6 = {68 78 35 37 74 39 62 6c 63 38 2e 64 6c 6c } //01 00  hx57t9blc8.dll
		$a_81_7 = {61 30 6a 36 7a 75 77 6f 77 67 77 30 72 6e 39 33 74 69 6f 71 6f 62 78 73 69 79 63 6b 35 } //01 00  a0j6zuwowgw0rn93tioqobxsiyck5
		$a_81_8 = {61 70 6d 68 6e 38 77 62 77 35 37 37 7a 34 79 76 64 74 6c 69 61 63 38 75 37 30 } //01 00  apmhn8wbw577z4yvdtliac8u70
		$a_81_9 = {61 71 63 64 71 79 37 71 6d 31 30 38 30 77 70 31 32 34 66 67 6b 7a 61 69 69 75 62 38 32 36 63 } //01 00  aqcdqy7qm1080wp124fgkzaiiub826c
		$a_81_10 = {64 6e 75 6f 69 6d 79 6a 34 61 79 30 32 70 33 68 76 39 66 39 71 6c 63 31 75 31 } //00 00  dnuoimyj4ay02p3hv9f9qlc1u1
	condition:
		any of ($a_*)
 
}