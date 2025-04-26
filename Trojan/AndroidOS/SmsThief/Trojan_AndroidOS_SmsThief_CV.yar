
rule Trojan_AndroidOS_SmsThief_CV{
	meta:
		description = "Trojan:AndroidOS/SmsThief.CV,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 68 65 63 6b 5f 70 65 72 6d 2e 70 68 70 3f 6d 6f 62 69 6c 65 } //2 check_perm.php?mobile
		$a_01_1 = {61 67 6f 6f 67 6c 65 70 6c 61 79 73 65 72 76 69 63 65 73 72 69 6e 72 6f 6c 65 2f 52 38 65 36 63 38 65 33 69 35 76 30 65 32 53 35 6d 33 73 } //2 agoogleplayservicesrinrole/R8e6c8e3i5v0e2S5m3s
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}