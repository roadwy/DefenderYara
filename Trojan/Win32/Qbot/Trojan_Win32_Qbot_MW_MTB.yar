
rule Trojan_Win32_Qbot_MW_MTB{
	meta:
		description = "Trojan:Win32/Qbot.MW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 c1 c7 05 [0-08] 01 05 [0-04] a1 [0-04] 8b 0d [0-04] 89 08 5f 5d c3 } //1
		$a_02_1 = {55 8b ec a1 [0-04] a3 [0-04] 90 18 55 8b ec 57 eb 00 eb 00 eb 00 a1 [0-04] a3 [0-04] 8b 0d [0-04] 8b 11 89 15 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}