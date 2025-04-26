
rule Trojan_Win32_Emotet_SR_MTB{
	meta:
		description = "Trojan:Win32/Emotet.SR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 53 56 57 [0-20] 74 ?? 57 e8 ?? ?? ?? ?? 59 50 8b c3 5a 8b ca 33 d2 f7 f1 8a 04 57 30 06 43 46 [0-06] 3b d8 75 e1 } //1
		$a_02_1 = {55 8b ec 53 56 57 [0-20] 74 ?? 56 e8 ?? ?? ?? ?? 59 50 8b c3 5a 8b ca 33 d2 f7 f1 8a 04 56 30 04 1f 43 3b 5d 10 75 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}