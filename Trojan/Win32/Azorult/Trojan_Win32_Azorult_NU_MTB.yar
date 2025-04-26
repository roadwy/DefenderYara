
rule Trojan_Win32_Azorult_NU_MTB{
	meta:
		description = "Trojan:Win32/Azorult.NU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {30 04 3b 81 [0-06] 90 18 47 3b 7d 08 90 18 81 [0-06] 90 18 e8 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}