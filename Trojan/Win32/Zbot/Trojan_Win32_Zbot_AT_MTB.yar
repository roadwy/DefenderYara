
rule Trojan_Win32_Zbot_AT_MTB{
	meta:
		description = "Trojan:Win32/Zbot.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {21 c1 29 f7 58 bb 07 00 00 00 83 eb 04 ba f3 21 40 00 f7 d3 f7 db 81 ff 52 64 00 00 fe 02 83 c2 fe 90 83 c2 03 81 fa 87 53 41 00 75 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}