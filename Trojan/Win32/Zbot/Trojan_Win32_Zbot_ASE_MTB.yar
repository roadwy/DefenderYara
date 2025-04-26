
rule Trojan_Win32_Zbot_ASE_MTB{
	meta:
		description = "Trojan:Win32/Zbot.ASE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {64 69 64 6c 65 72 35 00 1a 4f ad 33 99 66 cf 11 b7 0c 00 aa 00 60 d3 93 43 68 69 6e 61 6d } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}