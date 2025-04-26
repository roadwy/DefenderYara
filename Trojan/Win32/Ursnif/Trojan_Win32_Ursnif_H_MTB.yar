
rule Trojan_Win32_Ursnif_H_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {03 f0 8b 45 ?? 03 30 8b 4d ?? 89 31 [0-20] 8b e5 } //1
		$a_02_1 = {81 c1 3c 5e 00 00 a1 [0-40] 31 0d [0-10] c7 05 [0-20] a1 [0-20] 01 05 [0-20] 8b 15 [0-20] a1 [0-10] 89 02 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}