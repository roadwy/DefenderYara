
rule Trojan_Win32_Ursnif_GM_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b c0 31 0d 90 01 04 a1 90 01 04 8b ff c7 05 90 02 10 01 05 90 01 04 8b ff a1 90 02 10 8b 0d 90 01 04 89 08 90 00 } //1
		$a_02_1 = {8b 45 fc 89 45 f4 8b 0d 90 01 04 03 4d 90 01 01 89 0d 90 01 04 8b 55 90 01 01 89 55 90 01 01 8b 45 90 02 40 8d 84 0a 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}