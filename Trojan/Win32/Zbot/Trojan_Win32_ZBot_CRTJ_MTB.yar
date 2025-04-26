
rule Trojan_Win32_ZBot_CRTJ_MTB{
	meta:
		description = "Trojan:Win32/ZBot.CRTJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {a3 80 f0 e0 14 ff d6 68 38 20 e0 14 a3 84 f0 e0 14 ff d6 68 2c 20 e0 14 a3 88 f0 e0 14 ff d6 68 4c 12 e0 14 a3 8c f0 e0 14 ff d6 68 e0 11 e0 14 a3 90 f0 e0 14 ff d6 68 0c 12 e0 14 a3 94 f0 e0 14 ff d6 68 00 12 e0 14 a3 98 f0 e0 14 ff d6 8b 35 28 10 e0 14 68 1c 20 e0 14 ff 35 80 f0 e0 14 a3 9c f0 e0 14 ff d6 68 0c 20 e0 14 ff 35 80 f0 e0 14 a3 a0 f0 e0 14 ff d6 68 f8 1f e0 14 ff 35 80 f0 e0 14 a3 a4 f0 e0 14 ff d6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}