
rule Trojan_Win32_PsiXBot_PA_MTB{
	meta:
		description = "Trojan:Win32/PsiXBot.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 02 00 00 "
		
	strings :
		$a_02_0 = {ff 31 5e 83 c1 04 f7 de 83 ee 2d 83 c6 fe 83 ee ff 29 de 29 db 01 f3 c7 42 00 00 00 00 00 31 32 8d 7f 04 8d 52 04 81 ff ?? ?? 00 00 75 } //20
		$a_02_1 = {aa cb fb ff 29 ?? 24 83 ec 04 [0-10] aa cb fb ff 29 ?? 24 83 ec 04 [0-10] aa cb fb ff 29 ?? 24 83 ec 04 [0-10] 00 00 00 00 e8 } //1
	condition:
		((#a_02_0  & 1)*20+(#a_02_1  & 1)*1) >=21
 
}