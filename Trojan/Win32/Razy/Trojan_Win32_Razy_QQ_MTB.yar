
rule Trojan_Win32_Razy_QQ_MTB{
	meta:
		description = "Trojan:Win32/Razy.QQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {29 ff 01 ff e8 90 01 04 31 33 81 e8 90 01 04 43 81 c7 90 01 04 09 c7 39 cb 75 dd 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}