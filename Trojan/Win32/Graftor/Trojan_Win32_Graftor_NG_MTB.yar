
rule Trojan_Win32_Graftor_NG_MTB{
	meta:
		description = "Trojan:Win32/Graftor.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 55 ec b8 14 5c 41 00 e8 ?? ?? ff ff 8d 45 e8 e8 ?? ?? ff ff 8b 55 e8 a1 14 5c 41 00 e8 ?? ?? ff ff 75 7b e8 ?? ?? ff ff 84 c0 74 61 8d 45 e4 50 8d 55 e0 } //3
		$a_03_1 = {8d 55 c4 33 c0 e8 ?? ?? fe ff 8b 45 c4 b9 03 00 00 00 ba 01 00 00 00 e8 ?? ?? ff ff 8b 55 c8 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}