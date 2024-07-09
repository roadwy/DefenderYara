
rule Trojan_Win32_FormBook_MR_MTB{
	meta:
		description = "Trojan:Win32/FormBook.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 55 f4 8b 45 08 01 ?? 0f [0-02] 0f [0-02] 89 [0-02] 8b [0-02] 8b [0-02] 01 ?? 0f [0-02] 8b [0-02] 89 ?? 8b [0-02] 8b [0-02] 01 ?? 31 ?? 89 ?? 88 ?? 8b [0-02] 89 [0-02] 83 [0-03] 8b [0-02] 3b [0-02] 7c } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}