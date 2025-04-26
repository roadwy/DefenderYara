
rule Trojan_Win32_TrickBotCrypt_NA_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 4d ec 3b [0-04] 8b [0-02] 0f [0-02] 0f [0-03] 33 ?? 8b [0-02] 2b [0-02] 0f [0-02] 83 [0-02] 33 ?? 8b [0-02] 88 ?? 8b [0-02] 03 [0-02] 89 [0-02] eb } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}