
rule Trojan_Win32_Razy_QP_MTB{
	meta:
		description = "Trojan:Win32/Razy.QP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {09 f0 31 1f 81 c7 ?? ?? ?? ?? 01 c0 29 f6 39 d7 75 e2 81 ee ?? ?? ?? ?? 01 c6 c3 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}