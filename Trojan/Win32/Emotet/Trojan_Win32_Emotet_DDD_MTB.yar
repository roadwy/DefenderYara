
rule Trojan_Win32_Emotet_DDD_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {6a 00 50 e8 ?? ?? ?? ?? 8a 44 24 ?? 8a d0 8a cb f6 d2 0a c3 f6 d1 0a d1 22 d0 8b 44 24 ?? 88 10 40 83 6c 24 [0-02] 89 44 24 ?? 0f 85 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}