
rule Trojan_Win32_Qakbotcrypt_GA_MTB{
	meta:
		description = "Trojan:Win32/Qakbotcrypt.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {fc f3 a4 50 c7 04 [0-06] 59 ff b3 [0-04] 8f 45 [0-02] ff 75 [0-02] 58 55 81 04 [0-06] 29 2c [0-02] 83 65 [0-02] 00 ff 75 [0-02] 01 04 [0-02] 52 31 14 [0-04] 89 0c [0-04] 8d 83 } //1
		$a_02_1 = {58 59 c7 45 [0-02] 00 00 00 00 ff 75 [0-02] 01 04 [0-02] 8d 83 [0-32] 31 c9 31 c1 89 8b [0-04] 8b 4d [0-02] 31 c0 8b 04 [0-02] 83 ec fc ff e0 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}