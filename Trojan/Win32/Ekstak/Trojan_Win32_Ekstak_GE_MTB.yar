
rule Trojan_Win32_Ekstak_GE_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {53 56 57 31 c9 31 ff 00 00 50 8b 00 8b 70 ?? 01 f6 74 14 66 8b 3e 83 00 } //5
		$a_01_1 = {53 56 57 89 cf 31 db 00 00 eb 02 8b 00 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}