
rule TrojanClicker_Win32_Jaik_MBXU_MTB{
	meta:
		description = "TrojanClicker:Win32/Jaik.MBXU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {40 00 44 84 40 00 48 80 40 00 14 7a 40 00 d4 8a 40 00 } //2
		$a_01_1 = {48 19 40 00 5f fc 38 01 00 ff ff ff 08 00 00 00 01 00 00 00 03 00 01 00 e9 00 00 00 58 15 40 00 98 17 40 00 14 11 40 00 78 00 00 00 80 00 00 00 87 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}