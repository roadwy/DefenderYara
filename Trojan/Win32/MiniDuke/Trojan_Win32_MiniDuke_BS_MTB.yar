
rule Trojan_Win32_MiniDuke_BS_MTB{
	meta:
		description = "Trojan:Win32/MiniDuke.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 84 24 bc 00 00 00 30 02 89 f8 42 03 84 24 bd 00 00 00 39 c2 eb } //5
		$a_01_1 = {0f b6 02 42 34 b9 88 01 41 eb } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}