
rule Trojan_Win32_Darkgate_YAB_MTB{
	meta:
		description = "Trojan:Win32/Darkgate.YAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {50 89 d8 83 c0 ?? 48 48 48 48 } //1
		$a_01_1 = {48 48 48 58 31 d2 f7 f3 8a 04 16 30 04 0f } //10
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*10) >=11
 
}