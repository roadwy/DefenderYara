
rule Trojan_Win32_ClipBanker_BR_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.BR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {80 3b 6d 75 ?? 80 7b 01 6f 75 ?? 80 7b 02 6e 75 ?? 80 7b 03 65 75 ?? 80 7b 04 72 75 ?? 80 7b 05 6f 75 ?? 80 7b 06 3a 75 ?? 0f b6 43 07 83 e8 34 a8 fb 75 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}