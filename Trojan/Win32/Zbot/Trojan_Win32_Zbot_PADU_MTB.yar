
rule Trojan_Win32_Zbot_PADU_MTB{
	meta:
		description = "Trojan:Win32/Zbot.PADU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 f2 83 8b 45 50 03 fa 4b 89 0e ba 7b 00 ae 7c 81 c2 89 ff 51 83 03 f2 85 db 0f 84 d3 06 00 00 8b 0f 8b 55 d4 81 f2 c1 89 c0 0f 03 fa 4b 89 0e ba 45 55 ff 85 81 c2 bf aa 00 7a 03 f2 85 db 75 ba } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}