
rule Trojan_Win32_Yephiler_DA_MTB{
	meta:
		description = "Trojan:Win32/Yephiler.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 8c 0d [0-02] ff ff 01 c8 b9 00 01 00 00 99 f7 f9 0f b6 b4 15 [0-02] ff ff 8b 45 08 8b 8d [0-02] ff ff 0f b6 14 08 31 f2 88 14 08 8b 85 [0-02] ff ff 83 c0 01 89 85 [0-02] ff ff e9 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}