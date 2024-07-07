
rule Trojan_Win32_QQrob_RPY_MTB{
	meta:
		description = "Trojan:Win32/QQrob.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 e1 02 0b c1 88 45 df 0f b6 55 df f7 d2 88 55 df 0f b6 45 df 03 45 e0 88 45 df 0f b6 4d df c1 f9 03 0f b6 55 df c1 e2 05 0b ca 88 4d df 0f b6 45 df 83 c0 70 88 45 df 0f b6 4d df } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}