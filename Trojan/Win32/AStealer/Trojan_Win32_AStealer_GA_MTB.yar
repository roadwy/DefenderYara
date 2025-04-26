
rule Trojan_Win32_AStealer_GA_MTB{
	meta:
		description = "Trojan:Win32/AStealer.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_80_0 = {41 53 74 65 61 6c 65 72 } //AStealer  1
		$a_80_1 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 6c 6f 67 69 6e 73 } //SELECT * FROM logins  1
		$a_80_2 = {73 65 6c 65 63 74 20 2a 20 20 66 72 6f 6d 20 6d 6f 7a 5f 6c 6f 67 69 6e 73 } //select *  from moz_logins  1
		$a_80_3 = {50 4b 31 31 53 44 52 5f 44 65 63 72 79 70 74 } //PK11SDR_Decrypt  1
		$a_80_4 = {70 61 73 73 77 6f 72 64 } //password  1
		$a_80_5 = {73 6d 74 70 73 65 72 76 65 72 } //smtpserver  1
		$a_80_6 = {63 6f 6e 66 69 67 2e 64 79 6e 64 6e 73 } //config.dyndns  1
		$a_80_7 = {4a 44 4f 57 4e 4c 4f 41 44 45 52 } //JDOWNLOADER  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1) >=7
 
}