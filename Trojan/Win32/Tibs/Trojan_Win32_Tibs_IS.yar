
rule Trojan_Win32_Tibs_IS{
	meta:
		description = "Trojan:Win32/Tibs.IS,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {58 cd 2b b9 ?? ?? ?? ?? 81 e9 } //1
		$a_03_1 = {0f 6e c0 0f 7e 07 83 c7 ?? 83 ef ?? c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}