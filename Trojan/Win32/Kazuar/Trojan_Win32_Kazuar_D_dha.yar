
rule Trojan_Win32_Kazuar_D_dha{
	meta:
		description = "Trojan:Win32/Kazuar.D!dha,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f0 8b 00 69 d0 0d 66 19 00 8b 45 f0 89 10 8b 45 f0 8b 00 8d 90 90 5f f3 6e 3c 8b 45 f0 89 10 8b 45 f4 05 90 01 04 0f b6 10 8b 45 f4 83 e0 03 0f b6 44 05 eb 31 c2 8b 45 f4 05 90 01 04 88 10 83 45 f4 01 81 7d f4 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}