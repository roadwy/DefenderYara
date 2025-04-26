
rule Trojan_Win32_Gozi_RPK_MTB{
	meta:
		description = "Trojan:Win32/Gozi.RPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 75 c8 8b 36 0f b6 14 16 31 d1 8b 55 bc 8b 32 8b 55 b8 8b 12 88 0c 32 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}