
rule Trojan_Win32_LokibotCrypt_MU_MTB{
	meta:
		description = "Trojan:Win32/LokibotCrypt.MU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {81 ff 16 05 00 00 90 18 46 3b f7 90 18 e8 ?? ?? ?? ?? 30 } //1
		$a_02_1 = {55 8b ec 51 [0-04] 53 b8 [0-04] 8b [0-05] 01 [0-02] 01 [0-02] 8b [0-02] 8a [0-02] 8b [0-05] 88 [0-05] c3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}