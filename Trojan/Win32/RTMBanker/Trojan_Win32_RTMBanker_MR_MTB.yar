
rule Trojan_Win32_RTMBanker_MR_MTB{
	meta:
		description = "Trojan:Win32/RTMBanker.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {29 f6 2b 37 f7 de 83 ef ?? 83 ee ?? c1 ce ?? 29 d6 83 ee ?? 29 d2 29 f2 f7 da c1 c2 ?? d1 ca ?? ?? 8f 01 01 31 83 e9 ?? 83 eb ?? 8d 5b ?? 83 fb ?? 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}