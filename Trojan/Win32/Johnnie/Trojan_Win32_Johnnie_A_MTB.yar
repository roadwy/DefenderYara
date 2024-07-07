
rule Trojan_Win32_Johnnie_A_MTB{
	meta:
		description = "Trojan:Win32/Johnnie.A!MTB,SIGNATURE_TYPE_PEHSTR,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_01_0 = {4c 6f 67 69 6e 43 6f 6f 6b 69 65 20 6e 61 6d 65 3d } //1 LoginCookie name=
		$a_01_1 = {2f 73 63 6f 6f 6b 69 65 73 74 78 74 } //1 /scookiestxt
		$a_01_2 = {68 74 74 70 3a 2f 2f 68 66 75 69 65 33 32 2e 32 69 68 73 66 61 2e 63 6f 6d 2f } //10 http://hfuie32.2ihsfa.com/
		$a_01_3 = {6d 00 61 00 6e 00 61 00 67 00 65 00 72 00 2f 00 61 00 63 00 63 00 6f 00 75 00 6e 00 74 00 5f 00 73 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 2f 00 61 00 63 00 63 00 6f 00 75 00 6e 00 74 00 5f 00 62 00 69 00 6c 00 6c 00 69 00 6e 00 67 00 } //1 manager/account_settings/account_billing
		$a_01_4 = {61 00 75 00 74 00 6f 00 4c 00 6f 00 67 00 69 00 6e 00 43 00 6f 00 6f 00 6b 00 69 00 65 00 20 00 6e 00 61 00 6d 00 65 00 3d 00 } //1 autoLoginCookie name=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=13
 
}