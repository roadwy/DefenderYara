
rule Trojan_Win32_Ursnif_D_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b c3 8b ff c7 05 90 02 30 01 05 90 02 20 8b ff a1 90 01 04 8b 0d 90 01 04 89 08 90 00 } //1
		$a_02_1 = {03 4d fc 89 0d 90 01 04 8b 55 90 01 01 89 55 90 01 01 8b 45 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}