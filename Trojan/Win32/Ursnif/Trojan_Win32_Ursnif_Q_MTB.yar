
rule Trojan_Win32_Ursnif_Q_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.Q!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b ff c7 05 90 02 30 01 1d 90 02 20 8b ff a1 90 02 10 8b 0d 90 02 20 89 08 90 00 } //1
		$a_02_1 = {03 f0 8b 45 90 01 01 03 30 8b 4d 90 01 01 89 31 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}