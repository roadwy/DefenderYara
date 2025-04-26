
rule Trojan_Win32_QQpass_MX_MTB{
	meta:
		description = "Trojan:Win32/QQpass.MX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c6 45 fc 00 8b b5 dc fd ff ff 83 c6 f0 8d 7e 0c 83 c4 08 83 3f 00 8b d8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}