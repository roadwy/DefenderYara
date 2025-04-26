
rule Trojan_Win32_CryptInject_INJT_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.INJT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_01_0 = {84 5c d0 1f 10 20 48 26 e4 42 30 22 14 4b 2e 64 40 } //5
		$a_01_1 = {30 74 ec 8e 30 73 7f 2a 70 08 } //5
		$a_01_2 = {24 66 45 7c 43 d4 58 2b 86 48 40 6c ac c4 86 f4 d7 89 67 29 48 2f 1c fb 60 c1 7c 88 58 1b af 09 cb 74 f1 67 75 4b bf 18 94 ec d9 17 14 cf fc 41 6c 95 a2 47 df 98 92 0f 39 a2 ac 15 3f 3c 34 05 } //10
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*10) >=10
 
}