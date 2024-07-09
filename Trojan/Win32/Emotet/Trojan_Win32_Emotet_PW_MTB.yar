
rule Trojan_Win32_Emotet_PW_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 18 66 03 10 c3 b8 20 66 03 10 c3 e8 [0-04] 8b 48 ?? 83 08 ?? 89 48 ?? e8 [0-04] 8b 48 ?? 83 08 02 89 48 ?? c3 b8 d8 6c 03 10 c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}