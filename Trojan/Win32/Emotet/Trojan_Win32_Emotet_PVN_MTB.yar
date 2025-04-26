
rule Trojan_Win32_Emotet_PVN_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PVN!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 4d f3 03 c1 99 f7 fb 8b 45 e8 8a 4c 15 00 30 08 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}