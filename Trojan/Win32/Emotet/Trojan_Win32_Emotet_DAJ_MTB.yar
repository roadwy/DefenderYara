
rule Trojan_Win32_Emotet_DAJ_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 c8 04 6a 00 50 e8 ?? ?? ?? ?? 8a 44 24 18 8b 4c 24 1c 02 c3 0f b6 d0 8b 44 24 14 8a 54 14 20 30 14 01 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}