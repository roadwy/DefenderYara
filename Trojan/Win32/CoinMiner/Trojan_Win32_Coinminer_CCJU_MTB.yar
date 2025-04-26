
rule Trojan_Win32_Coinminer_CCJU_MTB{
	meta:
		description = "Trojan:Win32/Coinminer.CCJU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {51 00 30 00 c7 45 ?? 4e 00 32 00 c7 45 ?? 54 00 61 00 c7 45 ?? 51 00 75 00 c7 45 ?? 31 00 61 00 ff 15 } //2
		$a_03_1 = {30 32 58 25 c7 45 ?? 30 32 58 25 c7 45 ?? 30 32 58 00 } //1
		$a_03_2 = {61 70 70 64 c7 45 ?? 61 74 61 64 c7 45 ?? 2e 69 6e 69 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=4
 
}