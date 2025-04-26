
rule Trojan_Win32_Tibs_EX{
	meta:
		description = "Trojan:Win32/Tibs.EX,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {d1 e8 c1 e2 1f 8d 44 02 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-02] 81 76 fc ?? ?? ?? ?? (49|83) [0-02] 75 ?? c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}