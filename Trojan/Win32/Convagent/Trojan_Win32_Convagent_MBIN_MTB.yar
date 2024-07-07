
rule Trojan_Win32_Convagent_MBIN_MTB{
	meta:
		description = "Trojan:Win32/Convagent.MBIN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 eb 33 e8 2b fd 8b d7 c1 e2 04 89 54 24 10 8b 44 24 90 01 01 01 44 24 10 90 00 } //1
		$a_01_1 = {69 77 69 6d 75 00 00 64 61 76 6f 77 75 66 61 62 6f 79 69 78 69 70 69 6a 6f 72 } //1 睩浩u搀癡睯晵扡祯硩灩橩牯
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}