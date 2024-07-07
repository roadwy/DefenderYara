
rule Trojan_Win32_Emotet_DN_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DN!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 f5 8b 44 24 40 8b 6c 24 1c 2b d3 03 d7 8a 04 02 30 45 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}